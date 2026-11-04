# Classifier evaluator: finite confidence thresholds (2026-11-03)

## Defect and correction

The evaluator validated NaN and out-of-range confidence thresholds but did not explicitly reject positive or negative infinity. A positive infinite maximum false-positive bound could disable the intended safety constraint. A negative infinite minimum recall or precision threshold could likewise produce invalid qualification semantics. The CLI now rejects all non-finite threshold values before opening the corpus or emitting JSON. The six affected switches are `--max-fpr-upper`, `--min-recall-lower`, `--min-precision-lower`, `--max-cohort-fpr-upper`, `--min-cohort-recall-lower`, and `--min-cohort-precision-lower`.

Regression coverage checks all six switches with NaN and both infinity signs, verifies that no evaluation report is emitted, and separately checks the finite-value predicate. Existing range checks remain in place.

## Qualification boundary

This is a classifier **evaluation configuration** correction, not an improvement to detection itself. Independently labelled, representative ham/spam corpora, corpus provenance, precision/recall and false-positive measurements, exact-HEAD CI, and live Postfix/Dovecot qualification remain required. No running mail server is changed. Preserve native launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, persistent `/opt/spamgate/data`, and Milter ports 38470/38472. All GitHub issues #1–#9 remain subject to their acceptance criteria.

## Verification

The commit was created using the GitHub contents API. Local Git clone and Go test execution were blocked by DNS resolution of github.com in the execution container. Tests must be independently run with `go test ./cmd/spamgate-eval` and `go test ./...`; inspect exact-HEAD CI before claiming qualification.
