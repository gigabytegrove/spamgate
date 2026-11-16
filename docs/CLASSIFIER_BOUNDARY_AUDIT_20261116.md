# Classifier decision-boundary evidence (2026-11-16)

The offline evaluator supports `-audit-boundary-margin=N` with a finite, nonnegative score distance N. It reports, for each tenant, the count of independently labeled spam and clean samples whose classifier score lies within the inclusive interval around `-threshold`, plus exact ties and the fraction of that tenant's corpus near the boundary. The output field is `boundary_audit`. No live policy or mail disposition changes.

Example: `go run ./cmd/spamgate-classifier-eval -threshold=5 -audit-boundary-margin=0.25 < corpus.json`.

This is descriptive evidence: a high boundary concentration may warrant sensitivity testing, but no boundary fraction constitutes a statistically justified acceptance limit without an independently defined standard. Scores are not calibrated probabilities. This audit does not prove corpus representativeness, detect data leakage, or replace precision, recall and false-positive acceptance gates.

## Verification and limitations

Source and regression tests committed. Local checkout and execution unavailable because github.com DNS resolution failed in the execution environment; installed local Go is 1.23.2 whereas go.mod requires 1.27.4. Exact-final-HEAD CI and production Postfix/Dovecot acceptance must be checked separately. Issues #1–#9 remain open. Native Linux launcher, worker, data directory, and Milter ports remain unchanged.
