package transport

import (
    "errors"
    "fmt"

    "github.com/gigabytegrove/spamgate/internal/core"
)

// parkExhaustedLocked is called with the worker lease and queue mutex held.
// Every persisted "delivering" transition consumes an attempt before the
// network send. A crash can leave that attempt's SMTP outcome unknown, so an
// exhausted job must be retained for manual review rather than sent forever.
// This is an at-least-once queue; a manual Retry can duplicate accepted mail.
func (q *DeliveryQueue) parkExhaustedLocked(rec *spoolRecord, msg *core.Message) error {
    if rec.Attempts < MaxDeliveryAttempts {
        return errors.New("cannot park queue job before automatic attempt limit")
    }
    if rec.State != "delivering" && rec.State != "queued" {
        return errors.New("cannot park queue job outside retryable states")
    }
    rec.State = "dead"
    rec.Updated = q.now()
    if rec.LastError == "" {
        rec.LastError = "automatic attempt limit reached after interrupted SMTP delivery; upstream receipt unknown"
    }
    // Persist the non-deliverable state before updating the history mirror.
    // A failed mirror write must never make an exhausted original send again.
    if err := q.put(*rec); err != nil {
        return fmt.Errorf("cannot durably park exhausted SMTP original: %w", err)
    }
    msg.Delivery = "delivery_dead"
    msg.Findings = append(msg.Findings, core.Finding{
        Symbol: "QUEUE_DELIVERY_ATTEMPTS_EXHAUSTED",
        Source: "recovery/spool",
        Detail: "Automatic SMTP attempt ceiling reached, including interrupted in-flight attempts; original retained and upstream acceptance may be unknown",
    })
    if err := q.store.Save(*msg); err != nil {
        return fmt.Errorf("exhausted SMTP original retained but history persistence failed: %w", err)
    }
    return nil
}
