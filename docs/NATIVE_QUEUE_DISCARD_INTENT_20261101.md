# Native SMTP queue audited-discard crash recovery (2026-11-01)

Issues: #2 durable recovery, #6 diagnostics, #7 browser operations.

## Reproduced failure window

The prior DiscardWithAudit sequence wrote discard_requested to the history journal, then unlinked the queued original. A crash, unlink failure, or history persistence problem could leave the original eligible for automatic SMTP delivery despite an administrator having requested its destruction.

## Implemented state machine

The worker now durably publishes discard_pending in the synced spool before writing the audit journal. The queue does not process that state. If the journal fails, the original is retained and the API reports an error; an administrator may repair the journal and repeat the confirmed discard. Retry and the unaudited Discard method refuse pending discards. Queue inventory exposes discard_pending and the browser disables Retry while offering Finish discard.

For legacy interrupted journal-first operations, ProcessDue detects discard_requested history and persists discard_pending before attempting relay.

## Verification and limitations

Regression tests cover a blocked journal, queue restart, non-delivery, retry/delete refusal, completed audited discard and the legacy crash window. The normal full repository tests, race tests, vet, UI tests, Linux/Windows compilation and isolated Postfix/Dovecot CI must be checked separately.

This does not establish exactly-once SMTP delivery. A crash after remote 250 can still cause duplicates. A failed initial spool transition does not establish durable operator intent; the API reports failure. If the legacy history journal was entirely lost, its past discard request cannot be inferred from the original alone. No production mail host was modified, and real-host qualification remains outstanding.
