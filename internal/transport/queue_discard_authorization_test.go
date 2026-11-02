package transport

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestLegacyUnauditedDiscardCannotDeleteAcceptedOriginal(t *testing.T) {
	q, store, _ := newRecoveryQueue(t, func(context.Context, core.Message, []byte) error {
		t.Fatal("unexpected SMTP relay")
		return nil
	})
	id := core.ID()
	if err := q.Enqueue(core.Message{ID: id, Sender: "a@example.invalid", Recipients: []string{"b@example.invalid"}},
		[]byte("Subject: retained\r\n\r\noriginal")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(q.path(id))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := q.Discard(id); err == nil || !strings.Contains(err.Error(), "unaudited") {
			t.Fatalf("legacy deletion unexpectedly permitted: %v", err)
		}
	}
	after, err := os.ReadFile(q.path(id))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("legacy deletion changed the original")
	}
	if _, exists := store.Get(id); exists {
		t.Fatal("unaudited deletion unexpectedly wrote history")
	}
	if err := q.Discard("../../etc/passwd"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid queue ID not rejected: %v", err)
	}
}

func TestDiscardActorControlAndFormattingInjectionFailsWithoutMutation(t *testing.T) {
	q, store, _ := newRecoveryQueue(t, func(context.Context, core.Message, []byte) error {
		return nil
	})
	id := core.ID()
	if err := q.Enqueue(core.Message{ID: id, Sender: "a@example.invalid", Recipients: []string{"b@example.invalid"}},
		[]byte("Subject: retained\r\n\r\noriginal")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(q.path(id))
	if err != nil {
		t.Fatal(err)
	}
	invalid := []string{
		"", "  ", "admin\rforged", "admin\nforged", "admin\tforged",
		"admin\x00forged", "admin\u202eforged", "admin\u200bforged",
		"admin\u00a0forged", strings.Repeat("a", 129), string([]byte{0xff}),
	}
	for _, actor := range invalid {
		if err := q.DiscardWithAudit(id, actor); err == nil {
			t.Fatalf("accepted unsafe audit identity %q", actor)
		}
		after, err := os.ReadFile(q.path(id))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("invalid actor %q modified accepted original: %v", actor, err)
		}
		if _, exists := store.Get(id); exists {
			t.Fatalf("invalid actor %q wrote an audit event", actor)
		}
	}
	if err := q.DiscardWithAudit(id, "Renée Operator"); err != nil {
		t.Fatalf("valid Unicode operator name rejected: %v", err)
	}
	if _, err := os.Stat(q.path(id)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("audited discard did not remove original: %v", err)
	}
	msg, ok := store.Get(id)
	if !ok || msg.Delivery != "discarded" || msg.OverrideBy != "Renée Operator" {
		t.Fatalf("missing actor-attributed durable audit: %+v, exists=%t", msg, ok)
	}
}
