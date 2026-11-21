# Paired classifier regression gate — 2026-11-20

Command: `go run ./cmd/spamgate-corpus-compare -baseline before.jsonl -candidate after.jsonl -threshold 0.5 -max-new-fp 0 -max-new-fn 0`.

Both files must contain exactly the same independently labeled IDs with identical truth labels. Each line is a strict JSON object with exactly one non-null `id`, `truth`, and `score` field; duplicate or unknown fields, duplicate IDs, invalid scores and mismatched sample sets are refused. Order of lines does not matter. The tool reports baseline/candidate false-positive and false-negative totals, newly introduced errors, fixed errors, and sorted newly regressed IDs as JSON. Exit 0 means configured *paired regression* limits passed, 1 means regressions exceeded limits, 2 means invalid evidence or execution failure.

This does not prove production classification accuracy, representative sampling, low false-positive confidence bounds, or integration with the actual production scoring path. It complements, rather than replaces, `spamgate-corpus-eval`. A classifier change must use independently collected real clean/spam samples, versioned score generation, immutable labels, confidence-bound qualification and production-host acceptance.

Locked native Linux architecture unchanged. No service, Postfix or Dovecot configuration was modified. Go test execution and exact-HEAD CI are not verified by this commit.
