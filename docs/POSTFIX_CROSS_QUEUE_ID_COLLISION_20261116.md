# Cross-queue Postfix identity collision refusal — 2026-11-16

## Defect and correction

The HOLD parser previously tracked duplicate queue IDs only after filtering records to `queue_name == "hold"`. A contradictory `postqueue -j` snapshot containing an active or deferred queue entry with the same ID as a held message could therefore be treated as unambiguous release authorization evidence.

The parser now records valid queue IDs across **all queue classes** before applying the HOLD-only envelope requirements. Duplicate IDs across any two records reject the entire inventory. Unsafe non-HOLD queue IDs also reject the inventory. Ordinary non-HOLD records are not required to include HOLD-specific recipient, arrival, or size evidence. The existing HOLD correlation, release mutex, cross-process lock, durable intent audit, explicit opt-in, and privileged helper remain unchanged.

## Regression coverage

`internal/server/postfix_cross_queue_collision_test.go` tests active→hold, deferred→hold, hold→active, distinct IDs, and invalid non-HOLD IDs. Existing `postfix_hold_duplicate_records_test.go` continues testing repeated HOLD records and 1,000/1,001 capacity boundaries.

## Acceptance boundaries

This is an adversarial inventory integrity fix, not proof that Postfix actually emits contradictory snapshots. It does not prove successful release, final Dovecot mailbox placement, live ISPConfig compatibility, or no duplicate delivery. Verify Go tests and exact-HEAD CI before treating the change as qualified. No running mail server was modified. Preserve native launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, persistent `/opt/spamgate/data`, and Milter ports 38470/38472. Issues #1–#9 remain open until their independent end-to-end evidence exists.
