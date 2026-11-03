# Native spool pending/final immutable-original reconciliation — 2026-11-03

## Root cause
The read-only spool auditor previously incremented `pending_with_final` after checking that a published counterpart carried the pending queue ID, **before** comparing the immutable envelope/original digest. A different, independently signed message with the same ID was therefore both reported as `pending_conflict` and counted as a reconciled pending/final pair. The count could mislead an operator reviewing interrupted SMTP publication.

## Correction
`internal/spoolaudit/audit.go` now increments `PendingWithFinal` only after both the queue ID and immutable original digest match. A signed but conflicting original produces `pending_conflict` without incrementing the reconciled counter. No delivery, retry, replay, deletion, promotion or mail-server configuration change is performed.

`internal/spoolaudit/audit_test.go` tightens the existing conflicting-envelope assertion and adds a same-ID, different-original signed record regression, read-only byte preservation, and matching-original positive control.

## Qualification evidence and limits
GitHub source and previous HEAD were inspected. GitHub contents API commits were made to `main`. The local Git checkout attempt failed because `github.com` DNS resolution was unavailable. Exact-HEAD Go tests and workflow outcomes must be checked after this commit; no passing result is claimed here. Required: `go test ./internal/spoolaudit ./cmd/spamgate-spool-audit -count=1`, `go test ./... -count=1`, `go vet ./...`, isolated Postfix/Dovecot integration, and real-host SMTP acceptance/HOLD/delivery evidence.

## Open production gates
Issues #1–#9 remain cumulative: actual Postfix/Dovecot disposition and holds; durable delivery under crash, power loss and disk exhaustion; SMTP/authentication conformance; classifier detection and false-positive corpus; tenant policies; diagnostics and alerting; browser UI acceptance; backup/restore; native update and rollback. Preserve `/opt/spamgate/spamgate` as foreground launcher, `spamgate-worker`, persistent `/opt/spamgate/data`, and Milter ports 38470/38472. No Docker substitution or automatic changes to the running mail host.
