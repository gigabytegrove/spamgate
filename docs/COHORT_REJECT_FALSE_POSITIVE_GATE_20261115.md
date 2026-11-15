# Cohort-specific outright ham rejection gate — 2026-11-15

The offline classifier evaluator now reports Wilson 95% upper bounds for **outright rejection of legitimate mail** separately for every privacy-safe cohort. This is distinct from the existing aggregate ham rejection bound and from tag/quarantine/soft-reject interventions.

Invoke with `--require-cohorts --max-cohort-reject-fpr-upper=0.005` alongside representative independently adjudicated corpus requirements. A threshold below 1 without `--require-cohorts` is rejected rather than silently ignored. Non-finite and out-of-range thresholds are rejected. The default 1 disables the additional gate to preserve previous CLI acceptance semantics. Each cohort result now includes its rejection upper bound, configured maximum, and pass/fail decision; overall cohort qualification requires all populated cohorts to pass.

The regression corpus has two disjoint 1000-ham/1000-spam cohorts, with one rejected legitimate forwarded message. It verifies that a passing global rejection gate cannot conceal a failing minority cohort, that relaxing the cohort-specific threshold changes the outcome, and that invalid or unenforced options fail.

This is **offline evaluation only**. The test corpus is synthetic, not independently adjudicated production mail. Passing these tests does not establish classifier accuracy, production false-positive rates, Postfix/Dovecot disposition, tenant policy, durable delivery, or release qualification. No running mail host was changed.

Architecture remains locked: native foreground `/opt/spamgate/spamgate`, `spamgate-worker`, persistent `/opt/spamgate/data`, Milter ports 38470/38472, no Docker substitution.
