# Classifier corpus composition audit

Run `spamgate-classifier-eval -audit-corpus < labeled-corpus.json` to emit the existing evaluation plus `corpus_audit`. The audit reports overall clean/spam counts, lexicographically sorted per-tenant counts, and observed spam prevalence. It is read-only and does not modify mail disposition, tenant policy, Postfix, Dovecot, or persistent data.

The audit is intentionally descriptive, not an acceptance gate. It cannot verify independent labels, time-window coverage, deduplication by message content, sender/domain representativeness, leakage from training data, or the fidelity of production classifier scores. Those must be proven with a separately curated corpus and actual native pipeline evidence before declaring classifier qualification. Existing precision, recall and false-positive Wilson gates remain separate and opt-in.

Regression sources: `internal/qualification/corpus_audit_test.go` and `cmd/spamgate-classifier-eval/corpus_audit_integration_test.go`. The isolated GitHub CI run for the final commit must complete successfully before claiming these tests passed. No live mail-host qualification is implied.
