# Cohort precision confidence gate — 2026-11-03

Production issue #5 remains open. The existing global precision confidence threshold can conceal poor precision on a minority mail path. The new optional `--min-cohort-precision-lower` threshold (default 0) applies the same Wilson two-sided 95% lower confidence bound to every named, independently labelled cohort.

With `--require-cohorts`, each cohort must pass minimum ham/spam sample sizes, false-positive upper confidence bound, recall lower confidence bound, and the new precision lower bound. A cohort with no predicted positives cannot pass a positive precision threshold. JSON cohort results now include `precision`, `precision_lower_95` and `minimum_precision_lower_95`. The legacy evaluator function remains available and defaults the new threshold to disabled.

This is an offline corpus evaluation only. It neither changes running Postfix/Dovecot, the native launcher, worker, persistent storage, nor Milter ports. It does not prove corpus representativeness, calibrated accuracy on production mail, or real-host qualification. Exact-HEAD tests and CI must be independently checked; all nine production issues remain open until acceptance evidence exists.
