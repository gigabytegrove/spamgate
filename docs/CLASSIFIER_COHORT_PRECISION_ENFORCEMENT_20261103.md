# Classifier cohort precision configuration safety — 2026-11-03

## Defect and correction

The classifier evaluator accepted `--min-cohort-precision-lower` without `--require-cohorts`. Although per-cohort confidence was computed, the final exit status used only the global gate when cohort enforcement was disabled. An operator could therefore specify a positive safety threshold, receive exit status 0, and mistakenly believe that every cohort had passed.

The CLI now rejects a positive `--min-cohort-precision-lower` unless `--require-cohorts` is present. It returns configuration-error exit code 2, emits an actionable diagnostic to stderr, and does not emit a misleading JSON evaluation. Zero remains the compatibility-preserving disabled threshold. When both flags are supplied, existing cohort evaluation and exit-code-3 measured failures are preserved.

## Regression coverage

`TestCohortPrecisionThresholdRequiresEnforcement` checks positive thresholds 0.01, 0.8 and 1 without cohort enforcement; all must fail configuration without emitting JSON. `TestCohortPrecisionDisabledRemainsCompatible` checks that an explicit zero threshold still permits an unstratified corpus and successful global evaluation.

Run `go test ./cmd/spamgate-eval` and `go test ./...` on the exact final commit; CI and independent production-host verification must be reported separately.

## Qualification boundary

This is a classifier acceptance-configuration guard, not improved detection or evidence of corpus representativeness. GitHub issues #1–#9 remain open pending live Postfix/Dovecot qualification, durable failure injection, RFC conformance, representative precision/recall data, tenant policy and UI acceptance, diagnostics, backup/restore and native update/rollback. The permanent native launcher, worker, data directory and Milter ports are unchanged. No production mail host was modified.
