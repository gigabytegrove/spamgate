# Classifier acceptance threshold provenance — 2026-11-15

The JSON report's `qualification.thresholds` now records every global and
cohort acceptance threshold, including disabled-by-default reject/disruption
gates. This makes a reported pass/fail independently interpretable without
guessing which command-line flags or defaults were used.

## Evidence boundaries

The report includes configured minimum ham/spam samples, Wilson false-positive
upper limits, recall and precision lower limits, outright-rejection and
disruptive-disposition upper limits, and the equivalent cohort requirements.
The existing qualification evidence continues to include corpus digest status,
record and input budgets, and whether unique IDs and cohorts were required.
No corpus path, message content or sender/recipient identity is included.

A failed statistical gate still emits its complete JSON report with exit code 3.
Invalid input and operational errors return code 2 and do not imply a valid
evaluation. Passing a threshold does not establish corpus representativeness,
live SMTP correctness, mail-host delivery, or beta qualification.

## Verification

The new regression file exercises custom and default threshold provenance,
failure-report persistence, and corpus-path confidentiality. Actual Go
execution and exact-HEAD CI must be checked separately; committing tests is
not evidence that they passed. Production Postfix/Dovecot testing remains open.

Native deployment remains fixed: /opt/spamgate/spamgate foreground launcher,
spamgate-worker, /opt/spamgate/data, and Milter ports 38470/38472. This change
does not alter or restart a running mail server.
