# Native delivery worker cross-process lease — 2026-10-31

## Scope and observed defect

Issue #2 remains open. The durable SMTP outbox previously used a per-instance Go mutex to serialize `ProcessDue`. Two native worker processes pointed at the same `/opt/spamgate/data/delivery-queue` could both snapshot a due original before either persisted its `delivering` transition, causing concurrent relay of the same accepted original. The existing two-minute crash grace does not protect that initial race.

## Implementation

Linux `ProcessDue` now acquires an advisory `flock(LOCK_EX|LOCK_NB)` on the persistent `.delivery-worker.lock` file for the **entire pass**, including upstream SMTP calls, retry/dead-letter state, history finalization and directory sync. The lock is owned by the unprivileged native worker and is never unlinked. Its pathname is opened with `O_NOFOLLOW|O_CLOEXEC`; symlink, hardlink, non-private permissions, ownership mismatch and unsafe directory conditions fail closed. Contention returns `ErrDeliveryWorkerBusy` after 300 ms; the periodic queue runner silently skips a busy pass, while other errors remain visible. SMTP intake is not gated by this long-running worker lease.

A crash automatically releases the kernel lock. The durable `delivering` record and existing two-minute grace remain authoritative for uncertain upstream acknowledgements. No changes were made to Postfix, the Milter fail-open policy, launcher/worker split, or ports.

## Verification

The new lock implementation and its focused filesystem/concurrency tests were executed locally with Go 1.23 `go test -race` and `go vet` in an isolated test module. Full SpamGate package tests, cross-instance integration, CI, and isolated Postfix/Dovecot tests require separate exact-commit verification. This document does **not** claim live mail-host qualification.

## Remaining limitations and gates

The advisory lease coordinates cooperating native delivery workers only; manual spool manipulation and uncoordinated third-party programs can still race. `Enqueue`, `Retry`, `Discard`, and intake capacity checks are not yet protected by a shared cross-process mutation lock. A remote SMTP 250 followed by a crash remains at-least-once, with possible duplicate delivery. Non-Linux delivery processing now explicitly refuses to claim cross-process safety rather than silently proceeding without a lease; Windows requires its own native implementation before that platform is qualified. Disk-full, power-loss, queue corruption, independent live mail-host behavior and soak testing remain open.
