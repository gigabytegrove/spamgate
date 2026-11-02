package transport

import (
 "context"
 "errors"
 "fmt"
 "slices"

 "github.com/gigabytegrove/spamgate/internal/core"
)

// RetryWithAudit durably journals operator attribution before making a
// retained original eligible for SMTP replay. A prior interrupted send may
// already have been accepted upstream; delivery remains at-least-once.
func (q *DeliveryQueue) RetryWithAudit(id, actor string) error {
 actor, err := validateQueueDiscardActor(actor)
 if err != nil { return err }
 if !validQueueID(id) { return errors.New("invalid queue ID") }
 unlockWorker, err := acquireDeliveryWorkerLock(context.Background(), q.dir)
 if err != nil { return fmt.Errorf("cannot retry while delivery is active: %w", err) }
 defer unlockWorker()
 q.mu.Lock()
 defer q.mu.Unlock()
 rec, err := q.get(id)
 if err != nil { return err }
 switch rec.State {
 case "queued", "dead":
 case "discard_pending":
  return errors.New("finish the audited discard before retrying")
 default:
  return errors.New("message is in flight or already delivered")
 }
 msg, exists := q.store.Get(id)
 if !exists { msg = queueHistoryMessage(rec) }
 if msg.Delivery == "discard_requested" || msg.Delivery == "discarded" {
  return errors.New("cannot retry an original with a recorded discard intent")
 }
 // Reconcile stale history with the immutable spool envelope before audit.
 if msg.Sender != rec.Sender || !slices.Equal(msg.Recipients, rec.Recipients) {
  msg = queueHistoryMessage(rec)
  msg.Findings = append(msg.Findings, core.Finding{
   Symbol:"QUEUE_ENVELOPE_RESTORED", Source:"recovery/spool",
   Detail:"History envelope differed from durable spool before manual retry; original envelope restored",
  })
 }
 msg.Delivery = "retry_requested"
 msg.Findings = append(msg.Findings, core.Finding{
  Symbol:"QUEUE_RETRY_REQUESTED", Source:"manual/"+actor,
  Detail:"Operator requested a new SMTP delivery attempt; an interrupted prior attempt may already have been accepted upstream",
 })
 // Store.Save fsyncs the audit. Failure leaves retry eligibility unchanged.
 if err := q.store.Save(msg); err != nil {
  return fmt.Errorf("cannot persist operator retry audit; original retained: %w", err)
 }
 rec.State = "queued"
 rec.NextAttempt = q.now()
 rec.Updated = q.now()
 rec.Attempts = 0
 rec.LastError = ""
 if err := q.put(rec); err != nil {
  return fmt.Errorf("retry intent audited but durable queue reschedule is unconfirmed: %w", err)
 }
 return nil
}
