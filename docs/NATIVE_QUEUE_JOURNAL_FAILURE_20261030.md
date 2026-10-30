# Native SMTP queue: journal outage and interrupted publication

Scope: `gigabytegrove/spamgate`, native Linux launcher `/opt/spamgate/spamgate`,
worker `/opt/spamgate/spamgate-worker`, persistent `/opt/spamgate/data`.
This document describes engineering behavior, **not** a qualified live-host upgrade.

## Failure discovered

The prior `ProcessDue` transition wrote a `delivering` state and incremented
`attempts` before reconstructing or repairing the `events.jsonl` history.
If the journal could not be written, the function returned without sending any
SMTP message. Repeated failures consumed retry attempts and could eventually
dead-letter mail that was never handed to the upstream SMTP server.

A separate persistence path unconditionally removed `.pending-*` files on
`put` failure. When the file had been fully written, fsynced and closed, but
the rename failed, this erased the only unpublished original from that
attempt. The SMTP client still received a failure; losing that evidence made
forensic reconciliation more difficult.

## New behavior

- Missing or divergent history is reconstructed/corrected and durably saved
  **before** the queue changes to `delivering`, advances the retry counter,
  or calls the relay.
- On history failure, `ProcessDue` returns an error, leaves the published
  spool state unchanged, and does not call the SMTP relay.
- After a successful file fsync and close, failed publication retains the
  `.pending-*` file for manual investigation; partial or failed writes
  are removed.
- A failed directory fsync **after** a successful rename can leave a
  published file even when SMTP responds 451. This is an explicit
  at-least-once boundary: a client retry may create a duplicate.
- The queue inventory reads entries in bounded batches and refuses more
  than 4096 entries instead of loading an unbounded directory listing.
- Queue record reads check the opened file's size and modification time
  after reading, and reject negative attempt counters.

## Operational investigation (read-only)

Use the native auditor, built from the exact source revision under test:

```bash
/opt/spamgate/spamgate-spool-audit -dir /opt/spamgate/data/delivery-queue -json
```

A standalone auditor is optional and is not part of the required launcher
or worker service contract. Run the matching engineering binary from a
separate directory if it has not been installed.

If the auditor reports `pending_without_final`, do not rename the file to
a published queue job, retry it, or delete it. The SMTP sender may already
have retried, and an upstream server may already have accepted a copy.
Preserve the file and correlate with the SMTP session, Milter scan ID,
queue ID, and downstream logs before any operator recovery.

If `events.jsonl` is unavailable, repair its filesystem problem first.
Do not create a new empty history journal over an existing journal, and
do not force the queue to skip its history reconstruction. Keep a
consistent cold backup before invasive recovery.

## Regression tests

- `TestJournalOutageDoesNotConsumeDeliveryAttempt`: three failed attempts
  to reconstruct history leave one queued original at zero delivery
  attempts and zero relay calls; repair permits one delivery.
- `TestEnvelopeCorrectionOutageDoesNotConsumeAttempt`: a stale history
  envelope cannot be used for relay when the corrected history cannot be
  saved; repair restores the spool's authoritative recipient and sender.
- `TestSyncedPendingOriginalSurvivesRenameFailure`: failed rename retains
  the synced JSON record, original RFC822 bytes, and both digests.
- `TestQueueInventoryBoundsUnrelatedDirectoryEntries`: bounded inventory
  works at 4096 entries and refuses 4097.
- `TestQueueRejectsNegativeAttemptCounter`: impossible retry metadata
  is rejected even if its checksum is recomputed.

## Limitations and acceptance gates

These tests use a local temporary filesystem and injected path failures,
not actual disk-full, power-loss, fsync fault injection, or real Postfix
and Dovecot delivery. The queue remains **at-least-once**, not exactly-once.
It does not automatically replay ambiguous pending records, and a
successful remote SMTP 250 followed by a local crash may still duplicate.
A live-host rollback, cold restore, queue-ID correlation, and mailbox
placement check remain required before beta qualification.

The user's Postfix `milter_default_action = accept` is not changed.
No production mail host is modified by these source changes.
