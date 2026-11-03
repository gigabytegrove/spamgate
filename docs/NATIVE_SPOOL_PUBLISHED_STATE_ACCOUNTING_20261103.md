# Native spool published-filename state accounting — 2026-11-03

## Root cause
The read-only spool auditor reported `id_mismatch` for a published `<queue-id>.json` file whose embedded record ID differed, but still incremented `States[rec.State]`. A validly digested record placed under an unrelated queue filename could therefore inflate delivered, queued, or dead state totals despite an integrity finding.

## Correction
Published records with an embedded ID different from the filename's queue ID now contribute to the examined/published file counts and an explicit `id_mismatch` finding, but not to trusted delivery state totals. The auditor does not rewrite, release, retry, or delete any record. Pending-to-final reconciliation retains its separate embedded-ID and digest checks.

## Regression
`TestMisnamedSignedPublishedRecordExcludedFromStateTotals` supplies a valid signed delivered record under another queue ID's filename, alongside a correctly named queued record, and verifies only the correctly named record contributes to state totals. It also verifies the audit leaves the original bytes unchanged.

## Qualification evidence
GitHub commits are confirmed, but a full local checkout is blocked by DNS failure resolving github.com. No local Go test, Go vet, or exact-HEAD CI pass is claimed. Required checks: `go test ./internal/spoolaudit ./cmd/spamgate-spool-audit -count=1`, `go test ./... -count=1`, `go vet ./...`, exact-HEAD engineering CI and isolated Postfix/Dovecot CI, then production-host controlled end-to-end qualification.

## Unresolved gates
GitHub issues #1–#9 remain cumulative: actual Postfix HOLD/release and Dovecot mailbox disposition, durable queue recovery under power loss and disk-full, SMTP/authentication compliance, classifier breadth and measured false positives, tenant policy isolation, diagnostics/alerts, browser acceptance, backup/restore and native update/rollback. No production mail-host qualification is claimed. Preserve native launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, persistent `/opt/spamgate/data`, and Milter ports 38470/38472; never automatically alter the running mail server or substitute Docker. The October 31 beta target has passed without qualification.
