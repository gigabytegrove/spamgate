package transport

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

// The history mirror is not the SMTP delivery authority. A corrupted mirror
// must not turn a null reverse path into a sender or redirect a recipient.
func TestDeliveryQueueRestoresEnvelopeFromDurableSpool(t *testing.T) {
	dir := t.TempDir()
	store, err := core.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	original := core.Message{
		ID: core.ID(), Timestamp: time.Now().UTC(), Sender: "",
		Recipients: []string{"intended@example.net"}, Subject: "DSN",
		Connector: "smtp", Action: "tag", Score: 5,
		Findings: []core.Finding{{Symbol: "TEST_EVIDENCE", Source: "test", Score: 5}},
	}
	raw := []byte("From: other@example.org\r\nSubject: DSN\r\n\r\nStatus report\r\n")
	sends := 0
	queue, err := NewDeliveryQueue(dir, store, func(_ context.Context, m core.Message, b []byte) error {
		sends++
		if m.Sender != "" || len(m.Recipients) != 1 || m.Recipients[0] != "intended@example.net" {
			t.Fatalf("relay received forged or rewritten envelope: %+v", m)
		}
		if m.Action != "tag" || m.Score != 5 || string(b) != string(raw) {
			t.Fatalf("relay lost original scan evidence or bytes: %+v", m)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Enqueue(original, raw); err != nil {
		t.Fatal(err)
	}
	// Simulate a stale/corrupted events.jsonl mirror after SMTP 250.
	forged := original
	forged.Sender = "forged@example.org"
	forged.Recipients = []string{"attacker@example.net"}
	forged.Action = "accept"
	if err := store.Save(forged); err != nil {
		t.Fatal(err)
	}
	if err := queue.ProcessDue(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sends != 1 {
		t.Fatalf("expected one delivery, got %d", sends)
	}
	got, ok := store.Get(original.ID)
	if !ok || got.Sender != "" || len(got.Recipients) != 1 || got.Recipients[0] != "intended@example.net" || got.Action != "tag" {
		t.Fatalf("authoritative envelope and verdict not restored: %+v, present=%v", got, ok)
	}
	found := false
	for _, f := range got.Findings {
		if f.Symbol == "QUEUE_ENVELOPE_RESTORED" {
			found = true
		}
	}
	if !found {
		t.Fatalf("envelope repair not audited: %+v", got.Findings)
	}
	snapshot, err := queue.Snapshot()
	if err != nil || snapshot.Total != 0 {
		t.Fatalf("delivered spool not finalized: %+v %v", snapshot, err)
	}
}

func TestDeliveryQueueRefusesUnauditedEnvelopeRepair(t *testing.T) {
	dir := t.TempDir()
	store, err := core.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sends := 0
	queue, err := NewDeliveryQueue(dir, store, func(context.Context, core.Message, []byte) error {
		sends++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	msg := core.Message{ID: core.ID(), Timestamp: time.Now().UTC(), Sender: "",
		Recipients: []string{"recipient@example.net"}, Action: "accept", Connector: "smtp"}
	if err := queue.Enqueue(msg, []byte("From: from@example.org\r\n\r\nbody")); err != nil {
		t.Fatal(err)
	}
	forged := msg
	forged.Sender = "wrong@example.org"
	if err := store.Save(forged); err != nil {
		t.Fatal(err)
	}
	// A directory at the journal path causes a deterministic persistence
	// failure even when the test runs with root privileges.
	journal := filepath.Join(dir, "events.jsonl")
	if err := os.Remove(journal); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(journal, 0700); err != nil {
		t.Fatal(err)
	}
	err = queue.ProcessDue(context.Background())
	if err == nil || !strings.Contains(err.Error(), "authoritative queue envelope") {
		t.Fatalf("repair unexpectedly succeeded without durable audit: %v", err)
	}
	if sends != 0 {
		t.Fatal("relayed mail with unverified history repair")
	}
	snapshot, err := queue.Snapshot()
	if err != nil || snapshot.Total != 1 {
		t.Fatalf("accepted original was lost after repair failure: %+v %v", snapshot, err)
	}
}
