package core

// Locally trained Bernoulli naive Bayes classifier. Training is explicit,
// bounded, durable, and never loads raw messages into its persisted corpus.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const bayesMaxTerms = 100000

var bayesWord = regexp.MustCompile(`[a-z][a-z0-9]{2,24}`)

type BayesModel struct {
	Ham   uint64               `json:"ham"`
	Spam  uint64               `json:"spam"`
	Words map[string][2]uint32 `json:"words"` // [hamDocumentFrequency, spamDocumentFrequency]
}
type BayesScore struct {
	Probability float64 `json:"probability"`
	Ham         uint64  `json:"ham"`
	Spam        uint64  `json:"spam"`
	Ready       bool    `json:"ready"`
	Terms       int     `json:"terms"`
}

func bayesTokens(raw []byte) ([]string, error) {
	if len(raw) == 0 || len(raw) > 10<<20 {
		return nil, errors.New("Bayes message must be 1–10485760 bytes")
	}
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(message.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	text, _, _, _ := bodyParts(message.Header, data, 0)
	subject := decodedHeader(message.Header.Get("Subject"))
	// Include a lightly normalized high-signal vocabulary without retaining PII.
	input := strings.ToLower(subject + " " + text)
	seen := map[string]struct{}{}
	for _, word := range bayesWord.FindAllString(input, 3000) {
		if len(seen) >= 500 {
			break
		}
		seen[word] = struct{}{}
	}
	if len(seen) < 5 {
		return nil, errors.New("insufficient unique words for statistical training")
	}
	tokens := make([]string, 0, len(seen))
	for word := range seen {
		tokens = append(tokens, word)
	}
	sort.Strings(tokens)
	return tokens, nil
}
func (s *Store) loadBayes() error {
	s.bayes = BayesModel{Words: make(map[string][2]uint32)}
	raw, err := os.ReadFile(filepath.Join(s.dir, "bayes.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &s.bayes); err != nil {
		return fmt.Errorf("Bayes state: %w", err)
	}
	if s.bayes.Words == nil || len(s.bayes.Words) > bayesMaxTerms {
		return errors.New("Bayes model corrupted or too large")
	}
	return nil
}
func (s *Store) TrainBayes(raw []byte, label string) (BayesScore, error) {
	if label != "spam" && label != "ham" {
		return BayesScore{}, errors.New("label must be ham or spam")
	}
	tokens, err := bayesTokens(raw)
	if err != nil {
		return BayesScore{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.bayes
	if prev.Spam >= 100000 || prev.Ham >= 100000 {
		return BayesScore{}, errors.New("training sample limit reached")
	}
	next := BayesModel{Ham: prev.Ham, Spam: prev.Spam, Words: make(map[string][2]uint32, len(prev.Words)+len(tokens))}
	for k, v := range prev.Words {
		next.Words[k] = v
	}
	index := 0
	if label == "spam" {
		index = 1
		next.Spam++
	} else {
		next.Ham++
	}
	for _, word := range tokens {
		count, exists := next.Words[word]
		if !exists && len(next.Words) >= bayesMaxTerms {
			continue
		}
		count[index]++
		next.Words[word] = count
	}
	if err := atomicJSON(filepath.Join(s.dir, "bayes.json"), next); err != nil {
		return BayesScore{}, err
	}
	s.bayes = next
	return BayesScore{Ham: next.Ham, Spam: next.Spam, Ready: next.Ham >= 10 && next.Spam >= 10, Terms: len(next.Words)}, nil
}
func (s *Store) BayesStats() BayesScore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return BayesScore{Ham: s.bayes.Ham, Spam: s.bayes.Spam, Ready: s.bayes.Ham >= 10 && s.bayes.Spam >= 10, Terms: len(s.bayes.Words)}
}

// The displayed probability is a bounded, calibrated document-presence odds
// estimate, not a guarantee about mail safety or a standalone delivery verdict.
func (s *Store) ScoreBayes(raw []byte) (BayesScore, error) {
	tokens, err := bayesTokens(raw)
	if err != nil {
		return BayesScore{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	model := s.bayes
	out := BayesScore{Ham: model.Ham, Spam: model.Spam, Ready: model.Ham >= 10 && model.Spam >= 10, Terms: len(model.Words)}
	if !out.Ready {
		return out, nil
	}
	// Balance class priors: a ham-dominated inbox must not force ham verdicts.
	var logOdds float64
	for _, word := range tokens {
		count, ok := model.Words[word]
		if !ok {
			continue
		}
		pSpam := (float64(count[1]) + 1) / (float64(model.Spam) + 2)
		pHam := (float64(count[0]) + 1) / (float64(model.Ham) + 2)
		logOdds += math.Log(pSpam / pHam)
	}
	if logOdds > 30 {
		logOdds = 30
	}
	if logOdds < -30 {
		logOdds = -30
	}
	out.Probability = 1 / (1 + math.Exp(-logOdds))
	return out, nil
}
