package transport

import (
	"context"
	"testing"

	"github.com/gigabytegrove/spamgate/internal/core"
)

// Every published state must appear exactly once in the authenticated queue
// snapshot and metrics. Delivered records can remain while audit finalization
// is blocked; they must not silently disappear from operational counts.
func TestQueueSummaryCountsAllPublishedStates(t *testing.T) {
	q, _, _ := newRecoveryQueue(t, func(context.Context, core.Message, []byte) error {
		t.Fatal("inventory must not relay mail")
		return nil
	})
	states := []string{"queued", "delivering", "dead", "delivered", "discard_pending"}
	for _, state := range states {
		id := core.ID()
		if err := q.Enqueue(core.Message{ID: id, Sender: "from@example.invalid",
			Recipients: []string{"to@example.invalid"}}, []byte("Subject: count\r\n\r\nbody")); err != nil {
			t.Fatal(err)
		}
		if state != "queued" {
			rec, err := q.get(id)
			if err != nil { t.Fatal(err) }
			rec.State = state
			if err := q.put(rec); err != nil { t.Fatal(err) }
		}
	}
	got, err := q.Snapshot()
	if err != nil { t.Fatal(err) }
	if got.Total != 5 || got.Queued != 1 || got.Delivering != 1 ||
		got.Dead != 1 || got.Delivered != 1 || got.DiscardPending != 1 ||
		got.Total != got.Queued+got.Delivering+got.Dead+got.Delivered+got.DiscardPending {
		t.Fatalf("queue state inventory lost a published record: %+v", got)
	}
}
