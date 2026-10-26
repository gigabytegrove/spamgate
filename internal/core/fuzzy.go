package core

// Fuzzy matching uses locally stored 64-bit SimHash fingerprints derived from
// ordered word shingles. No message body is stored in the fuzzy corpus.
// It is an opt-in, administrator-trained near-duplicate signal; it is not a
// wire-compatible implementation of the distributed Rspamd fuzzy protocol.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	fuzzyMaxEntries    = 2500
	fuzzyLifetime      = 90 * 24 * time.Hour
	fuzzyDistanceLimit = 12
)

var fuzzyWords = regexp.MustCompile(`[a-z][a-z0-9]{2,24}`)

type FuzzyEntry struct {
	ID          string    `json:"id"`
	Fingerprint uint64    `json:"fingerprint"`
	Shingles    int       `json:"shingles"`
	Label       string    `json:"label"`
	Created     time.Time `json:"created"`
}
type FuzzyStats struct {
	Spam  int `json:"spam"`
	Ham   int `json:"ham"`
	Total int `json:"total"`
}
type FuzzyMatch struct {
	ID         string  `json:"id,omitempty"`
	Label      string  `json:"label,omitempty"`
	Similarity float64 `json:"similarity"`
	Distance   int     `json:"distance"`
	Matched    bool    `json:"matched"`
}

func fuzzyFingerprint(raw []byte) (uint64, int, error) {
	if len(raw) == 0 || len(raw) > 10<<20 {
		return 0, 0, errors.New("fuzzy sample must be 1–10485760 bytes")
	}
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid fuzzy sample: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(message.Body, 2<<20))
	if err != nil {
		return 0, 0, err
	}
	body, _, _, _ := bodyParts(message.Header, data, 0)
	// Shingle boundaries are deliberately preserved. A bag of words would
	// risk matching unrelated messages that use the same vocabulary.
	words := fuzzyWords.FindAllString(strings.ToLower(decodedHeader(message.Header.Get("Subject"))+" "+body), 5000)
	if len(words) < 18 {
		return 0, 0, errors.New("fuzzy matching requires at least 18 words")
	}
	var weights [64]int
	count := 0
	for i := 0; i+4 <= len(words); i++ {
		shingle := strings.Join(words[i:i+4], " ")
		h := sha256.Sum256([]byte(shingle))
		val := binary.BigEndian.Uint64(h[:8])
		for bit := 0; bit < 64; bit++ {
			if val&(uint64(1)<<bit) != 0 {
				weights[bit]++
			} else {
				weights[bit]--
			}
		}
		count++
	}
	var fingerprint uint64
	for bit, weight := range weights {
		if weight > 0 {
			fingerprint |= uint64(1) << bit
		}
	}
	return fingerprint, count, nil
}
func fuzzyActive(e FuzzyEntry, now time.Time) bool {
	return e.Created.After(now.Add(-fuzzyLifetime)) && !e.Created.After(now.Add(time.Hour))
}
func (s *Store) loadFuzzy() error {
	s.fuzzy = []FuzzyEntry{}
	raw, err := os.ReadFile(filepath.Join(s.dir, "fuzzy.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(raw) > 1<<20 {
		return errors.New("fuzzy database exceeds size limit")
	}
	if err = json.Unmarshal(raw, &s.fuzzy); err != nil {
		return fmt.Errorf("fuzzy database: %w", err)
	}
	if len(s.fuzzy) > fuzzyMaxEntries {
		return errors.New("fuzzy database exceeds entry limit")
	}
	seen := map[string]bool{}
	for _, e := range s.fuzzy {
		if e.ID == "" || seen[e.ID] || (e.Label != "spam" && e.Label != "ham") || e.Shingles < 15 || e.Shingles > 5000 || e.Created.IsZero() {
			return errors.New("invalid fuzzy database entry")
		}
		seen[e.ID] = true
	}
	return nil
}
func (s *Store) FuzzyStats() FuzzyStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now().UTC()
	var out FuzzyStats
	for _, e := range s.fuzzy {
		if fuzzyActive(e, now) {
			out.Total++
			if e.Label == "spam" {
				out.Spam++
			} else {
				out.Ham++
			}
		}
	}
	return out
}
func (s *Store) FuzzyEntries() []FuzzyEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]FuzzyEntry, 0, len(s.fuzzy))
	now := time.Now().UTC()
	for _, e := range s.fuzzy {
		if fuzzyActive(e, now) {
			out = append(out, e)
		}
	}
	return out
}
func (s *Store) TrainFuzzy(raw []byte, label string) (FuzzyEntry, error) {
	if label != "spam" && label != "ham" {
		return FuzzyEntry{}, errors.New("fuzzy label must be spam or ham")
	}
	fingerprint, shingles, err := fuzzyFingerprint(raw)
	if err != nil {
		return FuzzyEntry{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	active := make([]FuzzyEntry, 0, len(s.fuzzy)+1)
	for _, e := range s.fuzzy {
		if !fuzzyActive(e, now) {
			continue
		}
		if e.Fingerprint == fingerprint && e.Shingles == shingles {
			if e.Label != label {
				return FuzzyEntry{}, errors.New("sample already trained with opposite classification; delete it first")
			}
			return e, nil // idempotent
		}
		active = append(active, e)
	}
	if len(active) >= fuzzyMaxEntries {
		return FuzzyEntry{}, errors.New("fuzzy training limit reached; delete old samples")
	}
	entry := FuzzyEntry{ID: ID(), Fingerprint: fingerprint, Shingles: shingles, Label: label, Created: now}
	active = append(active, entry)
	if err = atomicJSON(filepath.Join(s.dir, "fuzzy.json"), active); err != nil {
		return FuzzyEntry{}, err
	}
	s.fuzzy = active
	return entry, nil
}
func (s *Store) DeleteFuzzy(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := make([]FuzzyEntry, 0, len(s.fuzzy))
	found := false
	for _, e := range s.fuzzy {
		if e.ID == id {
			found = true
			continue
		}
		entries = append(entries, e)
	}
	if !found {
		return errors.New("fuzzy fingerprint not found")
	}
	if err := atomicJSON(filepath.Join(s.dir, "fuzzy.json"), entries); err != nil {
		return err
	}
	s.fuzzy = entries
	return nil
}
func (s *Store) ScoreFuzzy(raw []byte) (FuzzyMatch, error) {
	fingerprint, shingles, err := fuzzyFingerprint(raw)
	if err != nil {
		return FuzzyMatch{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now().UTC()
	best := FuzzyMatch{Distance: 65}
	ambiguous := false
	for _, e := range s.fuzzy {
		if !fuzzyActive(e, now) {
			continue
		}
		// A similar SimHash alone is not sufficient: the text length must
		// also be comparable to avoid short-message false positives.
		if shingles*4 < e.Shingles*3 || e.Shingles*4 < shingles*3 {
			continue
		}
		distance := bits.OnesCount64(fingerprint ^ e.Fingerprint)
		if distance > fuzzyDistanceLimit {
			continue
		}
		if distance < best.Distance {
			best = FuzzyMatch{ID: e.ID, Label: e.Label, Distance: distance, Similarity: float64(64-distance) / 64, Matched: true}
			ambiguous = false
		} else if distance == best.Distance && e.Label != best.Label {
			ambiguous = true
		}
	}
	if ambiguous {
		return FuzzyMatch{}, nil
	} // fail neutral on equally close contradictory evidence
	if !best.Matched {
		return FuzzyMatch{}, nil
	}
	return best, nil
}
