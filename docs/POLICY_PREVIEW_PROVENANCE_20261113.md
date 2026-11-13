# Policy preview: score provenance and sample coverage (2026-11-13)

This change is confined to the read-only admin policy simulation endpoint.

- `items[].score_valid` distinguishes a legitimate historical score of zero from an invalid persisted score sanitized to zero for JSON transport. A false value means the historical score was NaN, infinite, negative, or above 1000; the item remains indeterminate and contributes no hypothetical disposition.
- `sample_coverage_percent` is the fraction of retained matching history examined, bounded to 0–100. An empty retained population with no examined items reports 100% coverage. Inconsistent metadata is bounded rather than presented as more than 100%.
- These values are **not** precision, recall, false-positive rates, delivery receipts, or live Postfix/Dovecot acceptance evidence.

Qualification still requires exact-commit Go tests and CI, real host SMTP transaction evidence, durable queue recovery, and independent production acceptance. No native launcher, worker, Milter port, mail-host configuration, or persistence location changes.
