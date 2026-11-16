# Per-tenant classifier evidence minimums — 2026-11-16

## Change
When an explicit `-expected-tenants` inventory is supplied with any classifier acceptance gate (`-max-fp-upper`, `-min-recall`, or `-min-precision`), each named tenant must contribute at least `-min-clean` legitimate and `-min-spam` malicious labeled examples. A nominal tenant with only one class is rejected before the evaluator writes any JSON report. Validation is deterministic by sorted tenant name. Exploratory runs without a classifier gate remain backward compatible.

## Boundaries
This is evidence sufficiency, not proof of representative data, absence of leakage, calibrated classification, or live mail-host disposition. It does not replace per-tenant Wilson bounds or production end-to-end testing. No Postfix, Dovecot, service, launcher, worker, Milter port, data directory or running mail configuration was changed.

## Verification
Source and regression tests committed. Exact-final-HEAD CI and actual production mail-host acceptance must be checked separately. All production issues #1–#9 remain subject to their own acceptance criteria.
