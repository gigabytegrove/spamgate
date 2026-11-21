# Paired classifier regression significance — 2026-11-21

## Scope
The native `spamgate-corpus-compare` command now emits `clean_regression_p_value` and `spam_regression_p_value` in its JSON report. These are exact **one-sided paired sign-test** probabilities for newly misclassified messages versus fixed misclassifications in the same labeled corpus. Clean and spam classes are evaluated independently. Unchanged classifications do not contribute to the discordant count. With no discordance the p-value is 1.

The implementation uses a log-domain binomial tail recurrence to avoid underflow on large paired corpora. The p-values are **diagnostic only**: they do not override the existing strict `max-new-fp`, `max-new-fn`, sample-count, observed-rate or Wilson upper-bound acceptance gates. Statistical significance is not evidence of operational safety or representative production accuracy. This is a paired sign test, not a confidence interval on production mail streams.

## Architecture and safety
No Postfix/Dovecot configuration, runtime service, Milter ports, data directory, or delivery action is changed. The locked native launcher `/opt/spamgate/spamgate`, `spamgate-worker`, persistent `/opt/spamgate/data`, and Milter ports 38470/38472 remain unchanged.

## Evidence and limitations
New source and table-driven Go tests are committed. The tests cover no discordance, symmetric discordance, extreme one-sided regressions, invalid counts, large corpora and JSON report integration. Full repository tests, GitHub Actions and real mail-host acceptance must be independently verified. No representative production clean/spam corpus was scored; this does not close issue #5 or any of issues #1–#9.

## Outstanding gates
Postfix/Dovecot final mailbox disposition and holds (#1/#9), durable delivery and recovery (#2), protocol and authentication conformance (#3), tenant policies (#4), production classifier scoring and independently labeled false-positive acceptance (#5), diagnostics (#6), browser workflow qualification (#7), and native backup/update/rollback (#8) remain open.
