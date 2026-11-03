# Native spool pending/final identity guard — 2026-11-03

## Root cause

The read-only spool auditor resolved a pending record's published counterpart using `<pending ID>.json` and verified the counterpart's internal integrity hashes. It did not require the published record's own signed `id` to equal the pending ID before incrementing `pending_with_final`. A valid, individually signed record belonging to another queue ID could therefore be counted as a reconciled final, despite the separate published filename mismatch finding.

## Change

`internal/spoolaudit/audit.go` now refuses to count such a record as a verified final and emits `pending_final_id_mismatch`. This is read-only forensic behavior: no queue record is replayed, removed, rewritten, acknowledged, or promoted. `internal/spoolaudit/audit_test.go` adds a mismatched signed-final fixture, checks read-only preservation, and verifies that a valid matching original is still recognized.

## Qualification

Inspect exact HEAD and run `go test ./internal/spoolaudit ./cmd/spamgate-spool-audit -count=1`, `go test ./... -count=1`, `go vet ./...`, and the isolated Postfix/Dovecot workflow. Record each result against the exact commit. These checks are not substitutes for production mail-host evidence. On this pass GitHub API edits succeeded, but local GitHub checkout was blocked by DNS resolution and exact-HEAD CI was not yet confirmed. No live mail server was changed.

## Still required

Issues #1–#9 remain open: actual Postfix/Dovecot disposition and HOLD evidence, crash/disk-full durable-delivery injection, protocol and authentication conformance, classifier precision/recall and false-positive corpus, tenant policy isolation, retained diagnostics and alerts, complete browser acceptance, cold backup/restore and native update/rollback. Preserve the native `/opt/spamgate/spamgate` foreground launcher, `spamgate-worker`, `/opt/spamgate/data`, and Milter ports 38470/38472. Never substitute Docker or modify running mail services automatically.
