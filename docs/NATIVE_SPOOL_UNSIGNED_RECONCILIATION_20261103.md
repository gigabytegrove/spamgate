# Native spool unsigned reconciliation evidence — 2026-11-03

## Defect and correction

The read-only delivery spool auditor accepted legacy records with absent integrity and state digests. Previously, a matching pending and published queue ID and recomputed immutable digest could increment `pending_with_final` even when one or both records lacked the stored integrity evidence. That inflated the count of verified reconciliations.

The auditor now reports `pending_final_unsigned` and does not increment `pending_with_final` unless both pending and published records carry complete, individually validated integrity and state digests. This check follows the queue-ID and immutable-original comparisons. The existing `legacy_unsigned` finding remains independently visible. This is an evidence-integrity guard, not cryptographic authentication: unkeyed SHA-256 fields are not proof of trusted origin.

## Regression scope

`TestPendingUnsignedRecordsCannotClaimVerifiedFinal` covers unsigned pending, unsigned published, both unsigned, read-only preservation and fully signed positive control. Required qualification: `go test ./internal/spoolaudit ./cmd/spamgate-spool-audit -count=1`, `go test ./... -count=1`, `go vet ./...`, exact-commit CI and real mail-host tests. Local checkout was unavailable because github.com DNS resolution failed; do not treat the new tests as passed without CI evidence.

## Remaining production gates

GitHub issues #1–#9 remain cumulative and open: real Postfix/Dovecot HOLD/release and mailbox disposition, crash/power-loss/disk-full durable delivery, SMTP/authentication conformance, classifier breadth and false-positive corpus, tenant policy isolation, diagnostics/alerting, complete browser acceptance, backup/restore and native update/rollback. No automatic mail-server modification or Docker substitution. Preserve `/opt/spamgate/spamgate` foreground launcher, `spamgate-worker`, `/opt/spamgate/data`, and Milter ports 38470/38472. The October 31 target passed; beta qualification is not established.
