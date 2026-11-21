# Native spool-trend evidence hardening — 2026-11-21

## Scope
The read-only `spamgate-spool-trend` utility now rejects duplicate JSON object keys at any nesting level, excessive nesting, trailing JSON values, oversized evidence and arithmetic overflow in spool audit counts. These checks are applied before accepting a report as qualification evidence.

The native Linux executable is compiled and smoke-tested by the engineering workflow. The smoke test expects a nonzero exit for a one-message queued-growth violation and verifies `gate_passed=false` in the resulting JSON.

## Safety boundaries
This command only reads previously captured reports. It does not read SMTP originals, change Postfix or Dovecot configuration, change Milter ports, release held mail, or alter the persistent spool. No host acceptance or production delivery claims follow from these tests.

Report files are still opened by pathname after `Lstat`; a hostile parent-directory replacement and in-place modification with restored timestamps remain unqualified. Reports do not contain a signed capture identity or timestamp, so the tool cannot prove chronological order or that both snapshots refer to the same host. It is not a source of delivery truth.

## Qualification
Run `go test -count=1 ./internal/spooltrend ./cmd/spamgate-spool-trend` and `go vet ./internal/spooltrend ./cmd/spamgate-spool-trend` with the repository's Go toolchain. The GitHub engineering workflow also runs repository-wide tests and compiles the native executable. Until exact-HEAD CI has completed successfully, these changes are committed but unqualified.

All nine production gates remain open. In particular, real Postfix/Dovecot mailbox disposition, durable crash-safe delivery, SMTP authentication conformance, measured classifier false positives, runtime tenant policy, complete browser acceptance, backup/restore and native update/rollback require independent evidence.
