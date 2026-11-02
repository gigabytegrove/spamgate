package transport

import (
    "bytes"
    "context"
    "errors"
    "strings"
    "testing"
    "time"

    "github.com/gigabytegrove/spamgate/internal/core"
)

func TestInterruptedRelayAtAttemptCeilingIsParkedWithoutAnotherSend(t *testing.T) {
    cases := []struct {
        name string
        state string
        attempts int
        lastError string
    }{
        {"inflight ceiling", "delivering", MaxDeliveryAttempts, ""},
        {"queued ceiling", "queued", MaxDeliveryAttempts, "last upstream timeout"},
        {"legacy over ceiling", "delivering", MaxDeliveryAttempts + 2, ""},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            dir := t.TempDir()
            store, err := core.Open(dir)
            if err != nil { t.Fatal(err) }
            sends := 0
            q, err := NewDeliveryQueue(dir, store, func(context.Context, core.Message, []byte) error {
                sends++
                return errors.New("unexpected relay")
            })
            if err != nil { t.Fatal(err) }
            raw := []byte("From: sender@example.invalid\r\nTo: recipient@example.invalid\r\n\r\nOriginal body\r\n")
            msg := core.Message{ID: core.ID(), Sender: "sender@example.invalid", Recipients: []string{"recipient@example.invalid"}, Action: "accept"}
            if err := q.Enqueue(msg, raw); err != nil { t.Fatal(err) }
            rec, err := q.get(msg.ID)
            if err != nil { t.Fatal(err) }
            rec.State = tc.state
            rec.Attempts = tc.attempts
            rec.LastError = tc.lastError
            rec.NextAttempt = time.Now().UTC().Add(-time.Minute)
            rec.Updated = time.Now().UTC()
            if err := q.put(rec); err != nil { t.Fatal(err) }

            // Restart the native worker after a simulated crash, then run it
            // repeatedly. Neither invocation may perform a seventeenth send.
            restarted, err := NewDeliveryQueue(dir, store, func(context.Context, core.Message, []byte) error {
                sends++
                return nil
            })
            if err != nil { t.Fatal(err) }
            for i := 0; i < 2; i++ {
                if err := restarted.ProcessDue(context.Background()); err != nil { t.Fatal(err) }
            }
            if sends != 0 { t.Fatalf("exhausted SMTP original sent %d times", sends) }
            got, err := restarted.get(msg.ID)
            if err != nil { t.Fatal(err) }
            if got.State != "dead" || got.Attempts != tc.attempts || !bytes.Equal(got.RawRFC822, raw) {
                t.Fatalf("original or attempt accounting changed: %+v", got.QueuedMessage)
            }
            if got.IntegritySHA256 != spoolDigest(got) || got.StateSHA256 != spoolStateDigest(got) {
                t.Fatal("parked original failed integrity verification")
            }
            if tc.lastError != "" && got.LastError != tc.lastError {
                t.Fatal("previous upstream diagnostic was overwritten")
            }
            history, ok := store.Get(msg.ID)
            if !ok || history.Delivery != "delivery_dead" { t.Fatalf("missing dead-letter history: %+v", history) }
            count := 0
            for _, finding := range history.Findings {
                if finding.Symbol == "QUEUE_DELIVERY_ATTEMPTS_EXHAUSTED" { count++ }
            }
            if count != 1 { t.Fatalf("expected exactly one durable exhaustion finding, got %d", count) }
            summary, err := restarted.Snapshot()
            if err != nil || summary.Dead != 1 || summary.Total != 1 {
                t.Fatalf("original was not retained for operator review: %+v %v", summary, err)
            }
        })
    }
}

func TestExhaustedOriginalRequiresExplicitManualRetry(t *testing.T) {
    dir := t.TempDir()
    store, err := core.Open(dir)
    if err != nil { t.Fatal(err) }
    sends := 0
    q, err := NewDeliveryQueue(dir, store, func(_ context.Context, _ core.Message, raw []byte) error {
        sends++
        if string(raw) != "durable original" { t.Fatal("relayed different bytes") }
        return nil
    })
    if err != nil { t.Fatal(err) }
    msg := core.Message{ID: core.ID(), Sender: "s@example.invalid", Recipients: []string{"r@example.invalid"}}
    if err := q.Enqueue(msg, []byte("durable original")); err != nil { t.Fatal(err) }
    rec, err := q.get(msg.ID)
    if err != nil { t.Fatal(err) }
    rec.State = "delivering"
    rec.Attempts = MaxDeliveryAttempts
    rec.NextAttempt = time.Now().UTC().Add(-time.Minute)
    rec.Updated = time.Now().UTC()
    if err := q.put(rec); err != nil { t.Fatal(err) }
    if err := q.ProcessDue(context.Background()); err != nil { t.Fatal(err) }
    if sends != 0 { t.Fatal("exhausted original relayed without operator action") }
    if err := q.Retry(msg.ID); err != nil { t.Fatal(err) }
    reset, err := q.get(msg.ID)
    if err != nil { t.Fatal(err) }
    if reset.Attempts != 0 || reset.State != "queued" || reset.LastError != "" {
        t.Fatalf("manual retry failed to reset durable state: %+v", reset.QueuedMessage)
    }
    if err := q.ProcessDue(context.Background()); err != nil { t.Fatal(err) }
    if sends != 1 { t.Fatalf("manual retry relayed %d times", sends) }
    summary, err := q.Snapshot()
    if err != nil || summary.Total != 0 { t.Fatalf("successful retry retained spool: %+v %v", summary, err) }
    history, ok := store.Get(msg.ID)
    if !ok || history.Delivery != "relayed" { t.Fatalf("retry not finalized: %+v", history) }
    found := false
    for _, finding := range history.Findings {
        if finding.Symbol == "QUEUE_DELIVERY_ATTEMPTS_EXHAUSTED" { found = true }
    }
    if !found { t.Fatal("manual retry erased prior exhaustion evidence") }
}

func TestExhaustionGuardRejectsInvalidDirectInvocation(t *testing.T) {
    q := &DeliveryQueue{}
    for _, tc := range []struct { state string; attempts int }{
        {"delivering", MaxDeliveryAttempts - 1},
        {"delivered", MaxDeliveryAttempts},
        {"discard_pending", MaxDeliveryAttempts},
    } {
        rec := spoolRecord{QueuedMessage: QueuedMessage{State: tc.state, Attempts: tc.attempts}}
        msg := core.Message{}
        if err := q.parkExhaustedLocked(&rec, &msg); err == nil || !strings.Contains(err.Error(), "cannot park") {
            t.Fatalf("unsafe direct invocation accepted: %+v, %v", tc, err)
        }
    }
}
