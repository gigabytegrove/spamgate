# Native SMTP spool forensic audit — 2026-10-30

## Purpose and scope

`spamgate-spool-audit` is a read-only tool for issue #2 (durable delivery) and issue #6 (operational diagnostics). It inspects `/opt/spamgate/data/delivery-queue` and verifies native spool JSON, original-message length, immutable envelope/original SHA-256 digest, and mutable delivery-state digest. It reports unpublished `.pending-*` files without exposing sender, recipient, subject, or message content. It **does not** deliver, promote, delete, retry, quarantine, release, or modify mail. Development does not touch the live mail server.

Build on native Linux: `go build -o spamgate-spool-audit ./cmd/spamgate-spool-audit`. Execute `./spamgate-spool-audit -dir /opt/spamgate/data/delivery-queue -json` with filesystem read permission. Exit 0 = no findings, 1 = operator review required, 2 = invalid invocation or I/O failure. Exit 0 is **not** proof of end-to-end delivery qualification.

## Crash-window handling

A `.pending-*` file can be a pre-rename intake, an older state update, or an interrupted write. Even a structurally valid pending record without a final record **does not establish that the remote SMTP client received 250**. When both pending and final exist, the pending copy may be older than the final, and replaying it may duplicate delivery. This utility never promotes or resends pending files. Preserve originals, compare queue ID and immutable digest, inspect SMTP transaction logs and queue history, and obtain operator authorization before any recovery action.

The audit reads bounded regular files, refuses symlinks and unsafe directory permissions, checks for changes while reading, and caps entries and findings. It is a best-effort observation on a live spool, **not** a transactionally consistent snapshot. If the worker is writing concurrently, rerun from a safe offline copy or correctly locked cold backup before drawing forensic conclusions. Legacy unsigned records are surfaced as unverified, not silently trusted. SHA-256 is corruption detection, not an authentication MAC against an attacker with write access.

## Qualification still outstanding

A clean audit does not prove final Dovecot mailbox placement or exactly-once delivery. Issue #2 still requires crash injection at each persistence boundary, disk-full and network faults, durable DSN behavior, duplicate-acknowledgement analysis, long soak, and real-host evidence. Issues #1 and #3–#9 remain independently open. No change to the native launcher, worker, Milter ports, persistent data layout, or Postfix `milter_default_action = accept` is authorized by this audit.
