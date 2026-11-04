# Classifier corpus sample-budget consistency — 2026-11-04

## Defect
The evaluator accepted `--min-ham` and `--min-spam` thresholds whose sum exceeded `--max-records`. Such a configuration cannot pass: the parser stops at the maximum accepted record count before the independently labelled minimums can both be satisfied. It previously opened and processed the corpus despite this contradiction.

## Correction
The CLI now rejects configurations when either minimum exceeds the record cap or the sum of both minima exceeds the cap. Arithmetic is promoted to int64 before addition, preventing int overflow on supported Go architectures. Exit code 2 indicates invalid configuration; no JSON report is emitted and the corpus is not opened. Exact-fit configurations remain permitted.

## Regression coverage
`go test ./cmd/spamgate-eval -run 'Test(ImpossibleSampleBudgetsRejectedBeforeCorpusOpen|FeasibleSampleBudgetReachesCorpusEvaluation)$' -count=1`

Tests cover each individual minimum exceeding the cap, the combined minimum exceeding it, large values near 32-bit integer limits, early rejection before corpus open, and an exact-fit passing evaluation.

## Evidence and remaining gates
The repository update was made through the GitHub contents API. Local Go tests were not executed in this pass because the runner could not resolve github.com for a checkout. Exact-HEAD CI and live Postfix/Dovecot behavior must be verified independently. This is a classifier-evaluation configuration fix, not proof of classifier precision, recall, corpus representativeness, or real mail delivery.

All production issues #1–#9 remain subject to full native Linux integration and regression qualification. The locked launcher, worker, persistent data directory, and Milter ports remain unchanged; no mail-host settings are modified.
