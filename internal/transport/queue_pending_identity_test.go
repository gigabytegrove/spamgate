package transport

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func retainAcceptedOriginal(t *testing.T, q *DeliveryQueue) (core.Message, string, []byte) {
	t.Helper()
	msg := core.Message{
		ID: core.ID(), Sender: "sender@example.invalid",
		Recipients: []string{"recipient@example.invalid"}, Action: "accept",
	}
	if err := q.Enqueue(msg, []byte("Subject: retained\r\n\r\noriginal")); err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(q.dir, ".pending-recovered")
	if err := os.Rename(q.path(msg.ID), pending); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(pending)
	if err != nil {
		t.Fatal(err)
	}
	return msg, pending, before
}

func TestEnqueueRefusesReusedIDFromCrashRetainedOriginal(t *testing.T) {
	q, _, dir := newIntegrityQueue(t)
	msg, pending, before := retainAcceptedOriginal(t, q)
	if err := q.Enqueue(msg, []byte("Subject: replacement\r\n\r\nother")); err == nil ||
		!strings.Contains(err.Error(), "reserved by retained unpublished") {
		t.Fatalf("reused identity accepted: %v", err)
	}
	after, err := os.ReadFile(pending)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("retained original changed: %v", err)
	}
	if _, err := os.Stat(q.path(msg.ID)); !os.IsNotExist(err) {
		t.Fatalf("colliding published original created: %v", err)
	}
	restarted, err := NewDeliveryQueue(dir, q.store, func(context.Context, core.Message, []byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Enqueue(msg, []byte("new")); err == nil {
		t.Fatal("restart forgot retained original identity")
	}
	if err := os.Remove(pending); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Enqueue(msg, []byte("Subject: restored\r\n\r\noriginal")); err != nil {
		t.Fatalf("operator-cleared collision did not resume intake: %v", err)
	}
}

func TestEnqueuePermitsIndependentIdentityWithValidPendingOriginal(t *testing.T) {
	q, _, _ := newIntegrityQueue(t)
	old, pending, before := retainAcceptedOriginal(t, q)
	next := core.Message{ID: core.ID(), Sender: "new@example.invalid", Recipients: []string{"other@example.invalid"}}
	if err := q.Enqueue(next, []byte("Subject: new\r\n\r\nbody")); err != nil {
		t.Fatalf("unrelated valid pending evidence blocked intake: %v", err)
	}
	after, err := os.ReadFile(pending)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("unrelated intake modified pending evidence: %v", err)
	}
	if next.ID == old.ID {
		t.Fatal("test identity collision")
	}
	summary, err := q.Snapshot()
	if err != nil || summary.Total != 1 || summary.PendingTemps != 1 {
		t.Fatalf("published and unpublished inventory changed: %+v %v", summary, err)
	}
}

func TestEnqueueFailsClosedOnAmbiguousPendingEvidence(t *testing.T) {
	q, _, _ := newIntegrityQueue(t)
	_, pending, before := retainAcceptedOriginal(t, q)
	changed := bytes.Replace(before, []byte(`"id":`), []byte(`"ID":"forged","id":`), 1)
	if bytes.Equal(changed, before) {
		t.Fatal("fixture did not inject ambiguous identity")
	}
	if err := os.WriteFile(pending, changed, 0600); err != nil {
		t.Fatal(err)
	}
	next := core.Message{ID: core.ID(), Sender: "sender@example.invalid", Recipients: []string{"recipient@example.invalid"}}
	if err := q.Enqueue(next, []byte("Subject: refused\r\n\r\nbody")); err == nil ||
		!strings.Contains(err.Error(), "ambiguous JSON") {
		t.Fatalf("ambiguous retained identity accepted: %v", err)
	}
	after, err := os.ReadFile(pending)
	if err != nil || !bytes.Equal(changed, after) {
		t.Fatalf("ambiguous evidence rewritten: %v", err)
	}
	if _, err := os.Stat(q.path(next.ID)); !os.IsNotExist(err) {
		t.Fatalf("unverified intake published: %v", err)
	}
}

func TestEnqueueFailsClosedOnTamperedPendingDigest(t *testing.T) {
	q, _, _ := newIntegrityQueue(t)
	_, pending, before := retainAcceptedOriginal(t, q)
	changed := bytes.Replace(before, []byte("sender@example.invalid"), []byte("altered@example.invalid"), 1)
	if bytes.Equal(changed, before) {
		t.Fatal("fixture did not alter original")
	}
	if err := os.WriteFile(pending, changed, 0600); err != nil {
		t.Fatal(err)
	}
	next := core.Message{ID: core.ID(), Sender: "sender@example.invalid", Recipients: []string{"recipient@example.invalid"}}
	if err := q.Enqueue(next, []byte("new")); err == nil ||
		!strings.Contains(err.Error(), "integrity verification") {
		t.Fatalf("tampered original did not fail closed: %v", err)
	}
}

func TestEnqueueFailsClosedOnUnparseablePendingEvidence(t *testing.T) {
	q, _, _ := newIntegrityQueue(t)
	pending := filepath.Join(q.dir, ".pending-partial")
	if err := os.WriteFile(pending, []byte(`{"id":`), 0600); err != nil {
		t.Fatal(err)
	}
	msg := core.Message{ID: core.ID(), Sender: "sender@example.invalid", Recipients: []string{"recipient@example.invalid"}}
	if err := q.Enqueue(msg, []byte("new")); err == nil ||
		!strings.Contains(err.Error(), "invalid or ambiguous JSON") {
		t.Fatalf("partial evidence did not stop intake: %v", err)
	}
	if err := os.Remove(pending); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(msg, []byte("new")); err != nil {
		t.Fatalf("intake failed after manual evidence removal: %v", err)
	}
}
