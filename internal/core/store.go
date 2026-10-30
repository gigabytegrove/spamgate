package core

import (
	"bufio"
 "context"
 "runtime"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Store struct {
	mu       sync.RWMutex
	dir      string
	cfg      Config
	messages map[string]Message
	bayes    BayesModel
	fuzzy    []FuzzyEntry
	neural   NeuralModel
	order    []string
	policy   deliveryPolicyState
	journalSize int64
	journalKnown bool
}

func ID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, cfg: DefaultConfig(), messages: make(map[string]Message)}
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err == nil {
		if e := json.Unmarshal(data, &s.cfg); e != nil {
			return nil, fmt.Errorf("config: %w", e)
		}
		// Legacy installs may have customized this field. The product name is fixed.
		s.cfg.Settings.SiteName = "SpamGate"
		if !s.cfg.Settings.Valid() {
			return nil, errors.New("invalid persisted settings")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := s.loadBayes(); err != nil {
		return nil, err
	}
	if err := s.loadFuzzy(); err != nil {
		return nil, err
	}
	if err := s.loadNeural(); err != nil {
		return nil, err
	}
	if err := s.loadDeliveryPolicy(); err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(dir, "events.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, e := f.Stat(); e == nil {s.journalKnown=true;s.journalSize=fi.Size()}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		var m Message
		if err := json.Unmarshal(scanner.Bytes(), &m); err != nil {
			return nil, fmt.Errorf("corrupt event log: %w", err)
		}
		if m.ID == "" {
			return nil, errors.New("missing event ID")
		}
		if _, ok := s.messages[m.ID]; !ok {
			s.order = append(s.order, m.ID)
		}
		s.messages[m.ID] = m
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	s.pruneLocked()
	return s, nil
}
func atomicJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	b = append(b, '\n')
	f, e := os.CreateTemp(filepath.Dir(path), ".spamgate-*.tmp")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(name, path)
}
func (s *Store) Config() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, _ := json.Marshal(s.cfg)
	var c Config
	_ = json.Unmarshal(b, &c)
	c.Settings.SiteName = "SpamGate"
	return c
}
func (s *Store) UpdateConfig(mut func(*Config) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(s.cfg)
	var next Config
	if e := json.Unmarshal(b, &next); e != nil {
		return e
	}
	if e := mut(&next); e != nil {
		return e
	}
	// Never persist a user-provided product name.
	next.Settings.SiteName = "SpamGate"
	if !next.Settings.Valid() {
		return errors.New("invalid settings thresholds or retention")
	}
	if len(next.RecipientPolicies) > 200 {
		return errors.New("too many recipient policies")
	}
	seenRecipients := map[string]bool{}
	for _, policy := range next.RecipientPolicies {
		key := strings.ToLower(policy.Mailbox)
		if !policy.Valid() || seenRecipients[key] {
			return errors.New("invalid or duplicate recipient threshold policy")
		}
		seenRecipients[key] = true
	}
	if e := atomicJSON(filepath.Join(s.dir, "config.json"), next); e != nil {
		return e
	}
	s.cfg = next
	return nil
}
func (s *Store) Save(m Message) error {
	if m.ID == "" {
		return errors.New("message ID required")
	}
	if len(m.HeaderSnapshot) > 0 && !validID(m.ID) {
		return errors.New("invalid scan ID for header persistence")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Persist the headers separately, using strict filesystem permissions; do
	// not put header contents in events.jsonl or normal message-list responses.
	if len(m.HeaderSnapshot) > 0 {
		dir := filepath.Join(s.dir, "headers")
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		if err := atomicBytes(filepath.Join(dir, m.ID+".hdr"), m.HeaderSnapshot); err != nil {
			return err
		}
	}
	m.HeaderSnapshot = nil
	m.HeaderTruncated = false
	b, e := json.Marshal(m)
	if e != nil {
		return e
	}
	b = append(b, '\n')
	path := filepath.Join(s.dir, "events.jsonl")
 if s.journalKnown {
  fi,e:=os.Lstat(path)
  if e!=nil{return fmt.Errorf("existing history journal missing: %w",e)}
  if !fi.Mode().IsRegular() || fi.Size()<s.journalSize{
   return errors.New("history journal deleted/truncated; refusing to append or overwrite forensic evidence")
  }
 }
 f, e := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e==nil { e=f.Sync() }
 var size int64
 if e==nil {if fi,statErr:=f.Stat();statErr==nil{size=fi.Size()}else{e=statErr}}
 closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {return closeErr}
 s.journalSize=size;s.journalKnown=true
 if _, ok := s.messages[m.ID]; !ok {
		s.order = append(s.order, m.ID)
	}
	s.messages[m.ID] = m
	prior := len(s.order)
	s.pruneLocked()
	if len(s.order) != prior {
		if err:=s.compactLocked();err!=nil{slog.Error("history compaction failed; original journal retained", "error",err)}
	}
	return nil
}
func (s *Store) Get(id string) (Message, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.messages[id]
	return m, ok
}
func (s *Store) List(limit int, email string) []Message {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	out := make([]Message, 0, limit)
	for i := len(s.order) - 1; i >= 0 && len(out) < limit; i-- {
		m := s.messages[s.order[i]]
		if email != "" && !containsAddress(m.Recipients, email) {
			continue
		}
		out = append(out, m)
	}
	return out
}
func containsAddress(xs []string, target string) bool {
	for _, x := range xs {
		if equalEmail(x, target) {
			return true
		}
	}
	return false
}
func (s *Store) Stats(email string) map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	counts := map[string]int{"accept": 0, "tag": 0, "quarantine": 0, "reject": 0, "soft_reject": 0}
	var sum float64
	count := 0
	for _, id := range s.order {
		m := s.messages[id]
		if email != "" && !containsAddress(m.Recipients, email) {
			continue
		}
		counts[m.Action]++
		sum += m.Score
		count++
	}
	avg := 0.0
	if count > 0 {
		avg = sum / float64(count)
	}
	return map[string]any{"total": count, "actions": counts, "average_score": avg, "version": Version}
}
func (s *Store) pruneLocked() {
	cutoff := time.Now().AddDate(0, 0, -s.cfg.Settings.RetentionDays)
	keep := make([]string, 0, len(s.order))
	for _, id := range s.order {
		m := s.messages[id]
		if m.Timestamp.Before(cutoff) {
			if e := os.Remove(filepath.Join(s.dir, "quarantine", id+".eml")); e != nil && !errors.Is(e, os.ErrNotExist) {
				slog.Error("expired quarantine purge failed", "id", id, "error", e)
			}
			if e := os.Remove(filepath.Join(s.dir, "headers", id+".hdr")); e != nil && !errors.Is(e, os.ErrNotExist) {
				slog.Error("expired headers purge failed", "id", id, "error", e)
			}
			delete(s.messages, id)
			continue
		}
		keep = append(keep, id)
	}
	if len(keep) > s.cfg.Settings.MaxHistory {
		n := len(keep) - s.cfg.Settings.MaxHistory
		for _, id := range keep[:n] {
			if e := os.Remove(filepath.Join(s.dir, "quarantine", id+".eml")); e != nil && !errors.Is(e, os.ErrNotExist) {
				slog.Error("evicted quarantine purge failed", "id", id, "error", e)
			}
			if e := os.Remove(filepath.Join(s.dir, "headers", id+".hdr")); e != nil && !errors.Is(e, os.ErrNotExist) {
				slog.Error("evicted headers purge failed", "id", id, "error", e)
			}
			delete(s.messages, id)
		}
		keep = keep[n:]
	}
	s.order = keep
}
func (s *Store) Compact() error {
 s.mu.Lock();defer s.mu.Unlock()
 audit,err:=s.auditHistoryLocked(context.Background())
 if err!=nil{return err}
 if audit.Status!="ok" && !(audit.Status=="missing"&&!s.journalKnown&&len(s.order)==0){
  return fmt.Errorf("refusing history compaction: %s (%s)",audit.Status,audit.Detail)
 }
 s.pruneLocked()
 return s.compactLocked()
}
func (s *Store) compactLocked() error {
	path := filepath.Join(s.dir, "events.jsonl")
	f, e := os.CreateTemp(s.dir, ".events-*.tmp")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	enc := json.NewEncoder(f)
	for _, id := range s.order {
		if e = enc.Encode(s.messages[id]); e != nil {
			f.Close()
			return e
		}
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e=os.Rename(name,path);e!=nil{return e}
 if fi,e:=os.Stat(path);e==nil{s.journalSize=fi.Size();s.journalKnown=true}else{return e}
 if runtime.GOOS!="windows" {
  directory,e:=os.Open(s.dir);if e!=nil{return e};defer directory.Close()
  if e=directory.Sync();e!=nil{return e}
 }
 return nil
}
func (s *Store) Quarantine(id string, raw []byte) error {
	if !validID(id) {
		return errors.New("invalid scan ID for quarantine persistence")
	}
	dir := filepath.Join(s.dir, "quarantine")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("quarantine path must be a real directory, not a symlink")
	}
	// Persist directory creation before acknowledging an SMTP quarantine.
	if err := syncAtomicParent(dir); err != nil {
		return err
	}
	return atomicBytes(filepath.Join(dir, id+".eml"), raw)
}
func atomicBytes(path string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".mail-*.tmp")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	return syncAtomicParent(path)
}

// The file fsync alone does not make a newly renamed directory entry
// crash-durable on native Unix filesystems.
func syncAtomicParent(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (s *Store) Quarantined(id string) ([]byte, error) {
	if !validID(id) {
		return nil, errors.New("bad ID")
	}
	return os.ReadFile(filepath.Join(s.dir, "quarantine", id+".eml"))
}
func (s *Store) RemoveQuarantine(id string) error {
	if !validID(id) {
		return errors.New("bad ID")
	}
	e := os.Remove(filepath.Join(s.dir, "quarantine", id+".eml"))
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	return e
}
func (s *Store) Export(w io.Writer) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := append([]string(nil), s.order...)
	sort.SliceStable(ids, func(i, j int) bool { return s.messages[ids[i]].Timestamp.Before(s.messages[ids[j]].Timestamp) })
	enc := json.NewEncoder(w)
	for _, id := range ids {
		if e := enc.Encode(s.messages[id]); e != nil {
			return e
		}
	}
	return nil
}

func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	b, e := hex.DecodeString(id)
	return e == nil && len(b) == 16
}

// DataDir is the configured persistent storage root for server state.
func (s *Store) DataDir() string { return s.dir }
