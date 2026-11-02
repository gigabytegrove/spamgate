package core

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHistoryJournalStrictDecoderRejectsAmbiguousEvidence(t *testing.T) {
	id := ID()
	valid := []byte(`{"id":"` + id + `","timestamp":"2026-11-02T11:00:00Z","action":"accept"}`)
	cases := map[string][]byte{
		"duplicate action": []byte(`{"id":"` + id + `","action":"accept","action":"reject"}`),
		"case alias": []byte(`{"id":"` + id + `","action":"accept","Action":"reject"}`),
		"unicode key alias": []byte(`{"id":"` + id + `","action":"accept","a\u0063tion":"reject"}`),
		"unpaired surrogate": []byte(`{"id":"` + id + `","subject":"\uD800","action":"accept"}`),
		"trailing value": append(append([]byte(nil), valid...), []byte(" true")...),
		"invalid utf8": append(append([]byte(nil), valid[:len(valid)-1]...), 0xff, '}'),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "events.jsonl")
			if err := os.WriteFile(path, append(append([]byte(nil), raw...), '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(dir); err == nil {
				t.Fatal("startup accepted ambiguous persisted history")
			}
			if _, err := decodeHistoryEvent(raw); err == nil {
				t.Fatal("common decoder accepted ambiguous history")
			}
		})
	}
	if _, err := decodeHistoryEvent(append(valid[:len(valid)-1], []byte(`,"future_field":"compatible"}`)...)); err != nil {
		t.Fatalf("non-conflicting forward-compatible history refused: %v", err)
	}
}

func TestHistoryReconciliationRefusesAmbiguousAppendWithoutMutation(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil { t.Fatal(err) }
	m := Message{ID: ID(), Timestamp: time.Now().UTC(), Action: "accept"}
	if err := s.Save(m); err != nil { t.Fatal(err) }
	path := filepath.Join(dir, "events.jsonl")
	before, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	bad := bytes.Replace(before, []byte(`"action":"accept"`), []byte(`"action":"accept","action":"reject"`), 1)
	if bytes.Equal(bad, before) { t.Fatal("test fixture did not create duplicate action") }
	if err := os.WriteFile(path, append(append([]byte(nil), before...), bad...), 0600); err != nil { t.Fatal(err) }
	original, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	if err := s.Save(Message{ID: ID(), Timestamp: time.Now().UTC(), Action: "tag"}); err == nil {
		t.Fatal("shared history reconciliation allowed a new append after ambiguous evidence")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(original, after) { t.Fatal("failed reconciliation modified forensic journal") }
}

func TestAuditHistoryDetectsFullRecordDriftAndMalformedEvidence(t *testing.T) {
	for _, tc := range []struct{ name, from, to, want string }{
		{"sender", `"sender":"original@example.invalid"`, `"sender":"forged@example.invalid"`, "mismatch"},
		{"recipient", `"recipients":["intended@example.invalid"]`, `"recipients":["other@example.invalid"]`, "mismatch"},
		{"delivery", `"delivery":"queued"`, `"delivery":"relayed"`, "mismatch"},
		{"action alias", `"action":"accept"`, `"action":"accept","Action":"reject"`, "corrupt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(dir)
			if err != nil { t.Fatal(err) }
			m := Message{ID: ID(), Timestamp: time.Now().UTC(), Sender: "original@example.invalid", Recipients: []string{"intended@example.invalid"}, Subject: "private subject", Action: "accept", Delivery: "queued"}
			if err := s.Save(m); err != nil { t.Fatal(err) }
			path := filepath.Join(dir, "events.jsonl")
			before, err := os.ReadFile(path)
			if err != nil { t.Fatal(err) }
			changed := bytes.Replace(before, []byte(tc.from), []byte(tc.to), 1)
			if bytes.Equal(changed, before) { t.Fatalf("fixture did not modify %s", tc.name) }
			if err := os.WriteFile(path, changed, 0600); err != nil { t.Fatal(err) }
			result, err := s.AuditHistory(context.Background())
			if err != nil { t.Fatal(err) }
			if result.Status != tc.want { t.Fatalf("unexpected audit result: %+v", result) }
			if strings.Contains(result.Detail, "original@") || strings.Contains(result.Detail, "intended@") || strings.Contains(result.Detail, "private subject") {
				t.Fatal("audit leaked private message data")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(changed, after) { t.Fatal("read-only audit changed forensic evidence") }
		})
	}
}
