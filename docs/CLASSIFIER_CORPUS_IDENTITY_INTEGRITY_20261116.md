# Classifier corpus sample identity integrity (2026-11-16)

The offline classifier evaluator rejects duplicate sample `id` values across the entire corpus, including across tenant boundaries. Repeated messages must not be counted as independent evidence because that can inflate confidence in measured false-positive rates, precision, and recall. The validator also rejects empty or whitespace-only `id` and `tenant` strings. Exact ID matching is case-sensitive; JSON escapes decode to their canonical string values before comparison.

The check runs before evaluation and report generation. A rejected corpus emits no JSON qualification report. Regression tests cover duplicate IDs across tenants, escaped identities, empty/whitespace provenance, case-distinct identities, and fail-before-report behavior.

These are corpus integrity safeguards, not evidence of classifier detection accuracy or production mail-host acceptance. They do not establish corpus independence or representativeness; corpus sourcing, contamination checks, real Postfix/Dovecot disposition, durable delivery, and all outstanding issue #1-#9 acceptance gates remain open. No production mail-server configuration or native launcher architecture changes are made.

Verification boundary: source and tests committed through GitHub; local checkout blocked by DNS resolution of github.com. Exact-final-HEAD Go tests, GitHub Actions results, and real-host acceptance must be independently verified.
