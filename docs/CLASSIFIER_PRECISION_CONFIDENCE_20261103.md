# Classifier precision confidence gate (2026-11-03)

The native `spamgate-eval` command now reports `precision_lower_95`, the Wilson two-sided 95% lower confidence bound on true positives among messages flagged as spam. The optional `--min-precision-lower` threshold (range 0–1; default 0) fails the corpus gate with exit code 3 if the bound falls below the requested value. Zero positive predictions cannot satisfy a positive threshold. Invalid arguments return exit code 2. The existing recall, false-positive, sample-size and optional cohort gates remain cumulative; default zero preserves existing automation behavior.

Example: `spamgate-eval --require-unique-ids --require-cohorts --min-precision-lower=0.95 --min-ham=1000 --min-spam=1000 labels.jsonl`.

This protects against treating a high observed precision on a small set of flagged messages as sufficient evidence. It does not substitute for representative independent labels, per-tenant evaluation, measured production false-positive rates, Postfix/Dovecot delivery evidence, or live mail-host qualification. Precision depends on corpus spam prevalence; compare against deployment prevalence before using the threshold for production enforcement. No mail-server configuration is modified.
