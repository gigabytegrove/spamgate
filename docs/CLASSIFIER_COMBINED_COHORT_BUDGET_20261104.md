# Simultaneous global and cohort sample-budget validation — 2026-11-04

Production issue #5. The previous evaluator checked global minimum ham/spam samples and the two required cohort minima separately. Both independent checks could pass even though no corpus within `--max-records` could satisfy them simultaneously. For example, with a record budget of 10, global ham minimum 8, and two required cohorts each needing 2 spam, at least 12 records are necessary.

When `--require-cohorts` is active, validation now computes the necessary ham budget as max(global minimum ham, twice per-cohort ham minimum) and likewise for spam, and rejects when their sum exceeds the record budget. Division and subtraction guard multiplication and addition against overflow. The check runs before the corpus is opened. Without cohort enforcement, existing report-only behavior is preserved.

Regression coverage includes global-ham-dominated, global-spam-dominated, mixed and large-integer configurations, early rejection, an exact-fit two-cohort corpus, and report-only compatibility.

Verification commands on the exact commit: `go test ./cmd/spamgate-eval -count=1` and `go test ./... -count=1`. This is a necessary feasibility condition, not proof of independent labels, classifier accuracy, Postfix/Dovecot operation, or a qualified beta. No native launcher, worker, persistent path, Milter port, or mail server was modified.
