package transport

import (
	"context"
	"errors"
	"net/textproto"
	"strings"
	"testing"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestQueuePermanentSMTPFailureRetainsOriginalAndManualRecovery(t *testing.T) {
	for _, stage := range []string{"MAIL", "RCPT", "DATA"} {
		t.Run(stage, func(t *testing.T) {
			sends := 0
			q, store, _ := newRecoveryQueue(t, func(context.Context, core.Message, []byte) error {
				sends++
				if sends == 1 {
					return wrapRelayStage(stage, &textproto.Error{Code: 550, Msg: "recipient policy denied"})
				}
				return nil
			})
			id := core.ID()
			raw := []byte("Subject: retained\r\n\r\noriginal mail\r\n")
			msg := core.Message{ID: id, Sender: "sender@example.invalid", Recipients: []string{"recipient@example.invalid"}}
			if err := q.Enqueue(msg, raw); err != nil {
				t.Fatal(err)
			}
			if err := q.ProcessDue(context.Background()); err != nil {
				t.Fatal(err)
			}
			summary, err := q.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if summary.Total != 1 || summary.Dead != 1 || summary.Jobs[0].Attempts != 1 {
				t.Fatalf("permanent 5xx should dead-letter after one attempt: %+v", summary)
			}
			rec, err := q.get(id)
			if err != nil || string(rec.RawRFC822) != string(raw) {
				t.Fatalf("original lost or changed: %v", err)
			}
			history, ok := store.Get(id)
			if !ok || history.Delivery != "delivery_dead" {
				t.Fatalf("dead-letter history missing: %+v", history)
			}
			found := false
			for _, finding := range history.Findings {
				if finding.Symbol == "QUEUE_DELIVERY_DEAD" && strings.Contains(finding.Detail, "permanently rejected") {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing permanent failure evidence: %+v", history.Findings)
			}
			if err := q.ProcessDue(context.Background()); err != nil {
				t.Fatal(err)
			}
			if sends != 1 {
				t.Fatalf("dead-letter retried without operator action: %d", sends)
			}
			if err := q.Retry(id); err != nil {
				t.Fatal(err)
			}
			if err := q.ProcessDue(context.Background()); err != nil {
				t.Fatal(err)
			}
			if sends != 2 {
				t.Fatalf("manual retry did not send once: %d", sends)
			}
			summary, err = q.Snapshot()
			if err != nil || summary.Total != 0 {
				t.Fatalf("manual retry did not finalize: %+v %v", summary, err)
			}
			history, ok = store.Get(id)
			if !ok || history.Delivery != "relayed" {
				t.Fatalf("delivered history missing: %+v", history)
			}
		})
	}
}

func TestQueueTransientSMTPAndAuthFailuresRemainRetryable(t *testing.T) {
	for _, tt := range []struct {
		name string
		err error
	}{
		{"upstream temporary 451", wrapRelayStage("RCPT", &textproto.Error{Code: 451, Msg: "try again"})},
		{"auth configuration 535", &textproto.Error{Code: 535, Msg: "authentication failed"}},
		{"network timeout", errors.New("connection timed out")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sends := 0
			q, _, _ := newRecoveryQueue(t, func(context.Context, core.Message, []byte) error {
				sends++
				return tt.err
			})
			msg := core.Message{ID: core.ID(), Sender: "sender@example.invalid", Recipients: []string{"recipient@example.invalid"}}
			if err := q.Enqueue(msg, []byte("Subject: transient\r\n\r\nbody")); err != nil {
				t.Fatal(err)
			}
			if err := q.ProcessDue(context.Background()); err != nil {
				t.Fatal(err)
			}
			summary, err := q.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if sends != 1 || summary.Total != 1 || summary.Queued != 1 || summary.Dead != 0 ||
				summary.Jobs[0].Attempts != 1 || summary.Jobs[0].LastError == "" {
				t.Fatalf("transient error incorrectly dead-lettered: sends=%d summary=%+v", sends, summary)
			}
			if err := q.ProcessDue(context.Background()); err != nil {
				t.Fatal(err)
			}
			if sends != 1 {
				t.Fatalf("transient retry bypassed backoff: %d", sends)
			}
		})
	}
}
