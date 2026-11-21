# Tenant-scoped paired classifier regression qualification — 2026-11-21

Production gates: #5 (classifier false positives/false negatives) and #4 (tenant isolation). This is offline qualification tooling, not a change to live mail disposition.

## Evidence contract

JSONL baseline and candidate records accept `id`, `truth` (`clean` or `spam`), `score` (0..1), and optional `tenant`. The strict decoder rejects duplicate, null, unknown and incorrectly typed keys. Paired records must have identical IDs, ground truth, and tenant identity. Unscoped historical corpora remain readable for exploratory comparisons.

For production acceptance, run `go run ./cmd/spamgate-corpus-compare -baseline baseline.jsonl -candidate candidate.jsonl -require-tenants -min-tenant-clean 100 -min-tenant-spam 100 -max-tenant-fpr 0.01 -max-tenant-fnr 0.10 -max-tenant-fpr-upper-95 0.05 -max-tenant-fnr-upper-95 0.20` with thresholds approved for the actual deployment. The existing global acceptance controls remain independent; defaults are permissive, so the operator must explicitly choose meaningful global and tenant thresholds. The command returns 0 on pass, 1 on measured regression, 2 on malformed evidence or configuration.

Each tenant receives paired new/fixed false-positive and false-negative counts, candidate rates, Wilson upper bounds, and exact paired sign-test probabilities. Tenant gate flags without `-require-tenants` are rejected, not silently ignored. Missing tenant IDs, insufficient clean/spam examples, or tenant drift prevent acceptance.

## Qualification boundaries

The implementation does not score messages itself. Production scoring integration, independently labeled representative corpora, real Postfix/Dovecot acceptance, durable delivery, authentication compliance, browser workflows, backup/restore, and native update/rollback remain outstanding. The October 31 beta target has passed. Do not declare beta readiness based on offline tests or isolated mail-lab success.

Locked native runtime remains unchanged: `/opt/spamgate/spamgate` foreground launcher, `spamgate-worker`, `/opt/spamgate/data` persistence, Postfix Milter ports 38470/38472. No automatic live mail-host changes.
