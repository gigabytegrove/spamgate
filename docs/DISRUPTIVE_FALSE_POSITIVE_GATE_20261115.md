# Delivery-disruption false-positive qualification — 2026-11-15

## Scope
The offline `spamgate-eval` evaluator now separately counts outright rejection, quarantine and temporary SMTP rejection for independently labelled ham and spam. Tag-only actions remain in the overall intervention false-positive metric but are **not** counted as delivery-disrupting actions. These categories are mutually exclusive per input record.

New optional flags:
- `--max-disruptive-fpr-upper=0.001` — Wilson 95% upper bound for the fraction of legitimate messages rejected, quarantined or temporarily rejected.
- `--require-cohorts --max-cohort-disruptive-fpr-upper=0.005` — independent bound in each privacy-safe cohort. Explicit active cohort thresholds without cohort enforcement fail argument validation.

Defaults are 1.0 for backwards compatibility; operators must explicitly enable these additional acceptance gates. A rejected legitimate message is counted in both outright-rejection and disruptive counters; it is counted **once** in the combined disruptive rate. This is a corpus evaluator, not an SMTP runtime behavior change.

## Tests and limitations
`TestDisruptiveDispositionGateAndCohorts` checks mixed tag, quarantine and soft-reject outcomes, global passing and minority-cohort failing safety bounds, and relaxation. `TestDisruptiveGateRefusesInvalidOrUnenforcedThreshold` checks non-finite/out-of-range arguments and refusal of an unenforced cohort threshold.

No independent corpus representativeness, measured production false-positive rate, real Milter action, queue delivery, Postfix/Dovecot hold, host-level restore or browser acceptance is established by this change. Issue #5 remains open, along with #1–#4 and #6–#9. Native launcher, worker, persistent data directory and Milter ports are unchanged. No production mail host was modified.
