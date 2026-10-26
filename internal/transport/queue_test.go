package transport

import (
	"context"
	"errors"
	"github.com/gigabytegrove/spamgate/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeliveryQueueRetryRecoveryAndDeadLetter(t *testing.T) {
	dir := t.TempDir()
	store, err := core.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: sender@example.com\r\nTo: user@example.net\r\nSubject: queue test\r\n\r\nBody\r\n")
	msg := core.Message{ID: core.ID(), Sender: "sender@example.com", Recipients: []string{"user@example.net"}, Subject: "queue test", Delivery: "queued", Timestamp: time.Now()}
	if err := store.Save(msg); err != nil {
		t.Fatal(err)
	}
	sends := 0
	send := func(_ context.Context, m core.Message, b []byte) error {
		sends++
		if string(b) != string(raw) || m.ID != msg.ID {
			t.Fatal("corrupted delivery")
		}
		if sends == 1 {
			return errors.New("temporary upstream rejection")
		}
		return nil
	}
	q, err := NewDeliveryQueue(dir, store, send)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(msg, raw); err != nil {
		t.Fatal(err)
	}
	s, err := q.Snapshot()
	if err != nil || s.Queued != 1 || s.Total != 1 || len(s.Jobs[0].Raw) != 0 {
		t.Fatalf("bad queue snapshot: %+v %v", s, err)
	}
	q2, err := NewDeliveryQueue(dir, store, send)
	if err != nil {
		t.Fatal(err)
	}
	if err := q2.ProcessDue(context.Background()); err != nil {
		t.Fatal(err)
	}
	s, _ = q2.Snapshot()
	if s.Jobs[0].Attempts != 1 || s.Jobs[0].State != "queued" || !strings.Contains(s.Jobs[0].LastError, "temporary") {
		t.Fatalf("retry state: %+v", s)
	}
	if err := q2.ProcessDue(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sends != 1 {
		t.Fatal("retried before backoff")
	}
	if err := q2.Retry(msg.ID); err != nil {
		t.Fatal(err)
	}
	if err := q2.ProcessDue(context.Background()); err != nil {
		t.Fatal(err)
	}
	s, _ = q2.Snapshot()
	if s.Total != 0 || sends != 2 {
		t.Fatalf("delivery job remained: %+v, sends=%d", s, sends)
	}
	m, _ := store.Get(msg.ID)
	if m.Delivery != "relayed" {
		t.Fatal("history not marked delivered")
	}
	if err := q2.Retry(msg.ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing job retry: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "delivery-queue", msg.ID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("raw mail remained on disk")
	}
}
func TestDeliveryQueueManualDiscardAndValidation(t *testing.T) {
	dir := t.TempDir()
	store, _ := core.Open(dir)
	q, _ := NewDeliveryQueue(dir, store, func(context.Context, core.Message, []byte) error { return errors.New("offline") })
	m := core.Message{ID: core.ID(), Sender: "a@example.org", Recipients: []string{"b@example.org"}}
	if err := q.Enqueue(m, []byte("message")); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(m, []byte("message")); err == nil {
		t.Fatal("duplicate ID allowed")
	}
	if err := q.Discard(m.ID); err != nil {
		t.Fatal(err)
	}
	s, _ := q.Snapshot()
	if s.Total != 0 {
		t.Fatal("not discarded")
	}
	if err := q.Discard("../../foo"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path traversal not denied: %v", err)
	}
}
