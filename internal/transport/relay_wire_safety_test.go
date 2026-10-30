package transport

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestRelayWireDataValidation(t *testing.T) {
	for _, tc := range []struct {
		name, raw, want string
	}{
		{"ordinary CRLF", "Subject: hi\r\n\r\nbody\r\n", ""},
		{"legacy LF", "Subject: hi\n\nbody\n", ""},
		{"eight bit UTF8", "Subject: caf\xc3\xa9\r\n\r\ncaf\xc3\xa9\r\n", ""},
		{"dot stuffed", "Subject: hi\r\n\r\n.hello\r\n", ""},
		{"no terminal newline", "Subject: hi\r\n\r\nbody", ""},
		{"empty", "", "empty"},
		{"binary NUL in body", "Subject: hi\r\n\r\na\x00b\r\n", "NUL"},
		{"binary NUL in header", "Subject: a\x00b\r\n\r\n", "NUL"},
		{"bare CR in header", "Subject: a\rb\r\n\r\n", "bare CR"},
		{"bare CR in body", "Subject: a\r\n\r\na\rb\r\n", "bare CR"},
		{"terminal bare CR", "Subject: hi\r\n\r\na\r", "bare CR"},
		{"long ASCII line", "Subject: hi\r\n\r\n" + strings.Repeat("a", 999) + "\r\n", "overlong"},
		{"long UTF8 byte count", "Subject: hi\r\n\r\n" + strings.Repeat("\xc3\xa9", 500) + "\r\n", "overlong"},
		{"long dot line", "Subject: hi\r\n\r\n." + strings.Repeat("a", 997) + "\r\n", "overlong"},
		{"max normal line", "Subject: hi\r\n\r\n" + strings.Repeat("a", 998) + "\r\n", ""},
		{"max dot line", "Subject: hi\r\n\r\n." + strings.Repeat("a", 996) + "\r\n", ""},
		{"long last line without newline", "Subject: hi\r\n\r\n" + strings.Repeat("a", 999), "overlong"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRelayWireData([]byte(tc.raw))
			if tc.want == "" && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
	if err := validateRelayWireData([]byte(strings.Repeat("a\r\n", 5<<20))); err == nil || !strings.Contains(err.Error(), "10 MiB") {
		t.Fatalf("oversized original accepted: %v", err)
	}
}

func TestInvalidOriginalErrorClassification(t *testing.T) {
	err := wrapInvalidRelayOriginal(errors.New("NUL"))
	if !isPermanentRelayFailure(err) {
		t.Fatal("deterministically invalid original must be permanent")
	}
	if !isPermanentRelayFailure(errors.Join(errors.New("context"), err)) {
		t.Fatal("wrapped invalid original lost its classification")
	}
	if isPermanentRelayFailure(errors.New("relay lacks 8BITMIME")) {
		t.Fatal("relay capability mismatch must remain retryable")
	}
	if wrapInvalidRelayOriginal(nil) != nil {
		t.Fatal("nil invalid-original error should stay nil")
	}
}

func TestQueueInvalidOriginalRetainedAsDeadLetter(t *testing.T) {
	sends := 0
	q, store, _ := newRecoveryQueue(t, func(_ context.Context, _ core.Message, raw []byte) error {
		sends++
		return wrapInvalidRelayOriginal(validateRelayWireData(raw))
	})
	id := core.ID()
	raw := []byte("Subject: binary\r\n\r\ninvalid\x00body\r\n")
	if err := q.Enqueue(core.Message{ID: id, Sender: "from@example.invalid", Recipients: []string{"to@example.invalid"}}, raw); err != nil {
		t.Fatal(err)
	}
	if err := q.ProcessDue(context.Background()); err != nil {
		t.Fatal(err)
	}
	summary, err := q.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if sends != 1 || summary.Dead != 1 || summary.Total != 1 || summary.Jobs[0].Attempts != 1 {
		t.Fatalf("invalid original was retried or lost: sends=%d summary=%+v", sends, summary)
	}
	rec, err := q.get(id)
	if err != nil || string(rec.RawRFC822) != string(raw) {
		t.Fatalf("immutable original not retained: %v", err)
	}
	msg, ok := store.Get(id)
	if !ok || msg.Delivery != "delivery_dead" {
		t.Fatalf("missing durable dead-letter history: %+v", msg)
	}
	found := false
	for _, f := range msg.Findings {
		if f.Symbol == "QUEUE_DELIVERY_DEAD" && strings.Contains(f.Detail, "invalid original") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing specific invalid-original evidence: %+v", msg.Findings)
	}
	if err := q.ProcessDue(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sends != 1 {
		t.Fatalf("dead-letter sent without operator retry: %d", sends)
	}
}
