# Native cross-process SMTP intake and admin mutation safety — 2026-10-31

## Failure mode and scope

Issue #2 remains open. The delivery worker's cross-process lease prevented two workers from relaying one original, but `Enqueue` still protected its inventory/capacity check with an instance-local mutex. Two independent SMTP intake processes could both pass the same capacity or queue-ID check. Separately, another process could retry or discard a job while the delivery worker had already selected it.

## Implemented

- Linux SMTP intake now takes a separate private `.delivery-intake.lock` flock across inventory, capacity, ID uniqueness and fsync-backed publication. Contention is bounded to two seconds and returns an error; callers must not acknowledge SMTP acceptance when it fails. This lock is independent of the long-lived `.delivery-worker.lock`, so a slow upstream SMTP transaction does not block new intake.
- Operator Retry, Discard and DiscardWithAudit acquire the same delivery-worker lease as `ProcessDue` before inspecting or changing spool state. They refuse with a busy error after 300 ms rather than modifying a job during another process's SMTP transaction.
- Both locks use `O_NOFOLLOW`, owner/link-count/permission checks, inode revalidation, and advisory `flock`; lock files are never unlinked.
- The implementation does not change the permanent foreground launcher, worker, persistent data root, Postfix fail-open behavior, Milter ports or live host.

## Tests and qualification boundaries

Regression coverage includes independent intake handles racing the same queue ID, unsafe intake lock paths, manual mutations during an in-flight cross-process relay, and continued intake while the upstream SMTP send is blocked. Exact-commit CI and isolated Postfix/Dovecot qualification must be reported separately from source implementation. No real production mail host has been modified.

**Still open:** cross-process store/journal coordination with independently opened `core.Store` instances; capacity/power-loss failure injection; possible duplicate upstream delivery after a remote SMTP 250 followed by a crash; durable cleanup/reconciliation of uncertain directory fsync; real-host and soak evidence; Windows native lock implementation. This is at-least-once delivery, not exactly-once.
