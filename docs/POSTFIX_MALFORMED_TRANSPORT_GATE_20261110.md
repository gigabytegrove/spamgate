# Postfix transport evidence: malformed-record fail-closed gate (2026-11-10)

This change affects the **offline qualification correlator only**. It does not alter SpamGate's native launcher, worker, persistent data directory, Milter listeners, Postfix configuration, or a live mail server.

## Why this matters

A queue may emit a successful `status=sent` record alongside a second malformed transport record. Previously, the correlator only recognized transport lines containing a syntactically valid `to=<recipient>` field. A missing or empty recipient, or a duplicated recipient assignment, could be ignored and a later successful record could still qualify the queue. Likewise, `status=, status=sent`, `dsn=, dsn=2.0.0`, and `nrcpt=, nrcpt=1` could hide malformed duplicate fields because the field scanners skipped empty values.

The correlator now observes transport **queue identity independently of the recipient field**. If a recognized Postfix transport-agent record is incomplete, has duplicate recipient/status assignments, or has an invalid recipient, it marks the associated run `ambiguous_queue_identity`. If that evidence appears before cleanup, the queue identity is retained as unsafe for later correlation. Empty DSN and queue-manager recipient-count assignments are also counted and rejected.

## Regression scope

The integrity suite covers missing/empty/duplicate transport recipients, an empty status followed by a valid status, a pre-cleanup malformed transport record, empty-plus-valid DSN and queue-recipient counts, and isolation of unrelated malformed queues. Existing successful single-recipient transport remains a **transport-only** result, never proof of Dovecot INBOX/Junk placement.

## Qualification boundaries

- No production Postfix/Dovecot host was exercised by this change.
- The engineering workflow invokes `python3 scripts/test-spamgate-postfix-report-integrity.py -v` on each push.
- Until that exact-HEAD workflow passes, these tests are committed but not independently verified.
- Issue #1 still requires real-host, recipient-bound, timestamped, next-hop and mailbox evidence; issues #2–#9 remain cumulative production gates.
