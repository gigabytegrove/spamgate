# Spool audit capture chronology — 2026-11-21

## Contract

The read-only native spool auditor emits `captured_at` as an RFC 3339 UTC timestamp at the start of its filesystem observation. This is **not** a transactional snapshot, durable delivery receipt, or authenticated host identity. Existing spool audit report fields and the foreground launcher/worker remain unchanged.

The spool trend comparator rejects timestamped reports in reversed or equal capture order, mixed timestamped and legacy reports, and implausible capture timestamps (before 2020 or more than five minutes into the future). Two legacy reports without timestamps remain supported for compatibility, but their chronological ordering is **unverified**. Never use legacy comparisons alone as qualification evidence. A malicious actor with write access to reports can forge capture times; store evidence in trusted directories.

## Validation and limitations

Unit tests: `go test ./internal/spooltrend ./internal/spoolaudit ./cmd/spamgate-spool-trend ./cmd/spamgate-spool-audit`. Follow with `go test ./...` and the existing native engineering and isolated Postfix/Dovecot CI. A local checkout was unavailable due to GitHub DNS resolution in this pass, so these tests were committed but not locally executed. GitHub Actions success must be checked against the exact final commit.

Outstanding production gates #1–#9 remain open. Capture timestamps do not prove final mailbox disposition, delivery durability, classifier accuracy, or production host readiness. No mail server or service was modified.
