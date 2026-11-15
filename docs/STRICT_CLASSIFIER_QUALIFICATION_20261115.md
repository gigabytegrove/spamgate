# Strict classifier corpus qualification — 2026-11-15

The offline `spamgate-eval --qualification-mode` option adds a fail-closed acceptance profile. It requires:

- `--require-unique-ids`: each independently adjudicated record has a unique lowercase SHA-256 identifier.
- `--require-cohorts`: at least two disjoint, sufficiently powered fixed privacy-safe cohorts, with no unclassified records.
- `--corpus-sha256=<64 lowercase hex>`: pin the entire JSONL corpus bytes, including ordering and whitespace.
- Explicit global and cohort false-positive, recall, precision, outright-rejection and delivery-disruption thresholds.
- Active precision thresholds above zero and rejection/disruption thresholds below one.

The existing sample-size defaults and all normal range checks still apply. This mode does not select acceptable production thresholds on behalf of the operator. A passing report is only evidence for the exact labelled corpus and thresholds supplied. Reusing the same message with a different digest, incorrect independent labels, or nonrepresentative cohorts remains a human-data-quality risk.

## Verification and scope

The regression source `qualification_mode_test.go` covers missing integrity gates, missing thresholds, a disjoint 4,000-record corpus, JSON pass reporting and digest mismatch refusal. GitHub CI and local execution must be inspected separately before claiming these tests passed.

No live Postfix/Dovecot qualification, native update/rollback, backup/restore, tenant policy, UI acceptance or mail-host modifications are part of this change. Issues #1–#9 remain open. Preserve `/opt/spamgate/spamgate`, `spamgate-worker`, `/opt/spamgate/data`, and Milter ports 38470/38472.
