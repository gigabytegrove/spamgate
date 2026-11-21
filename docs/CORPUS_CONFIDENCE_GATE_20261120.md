# Classifier corpus qualification: confidence-aware false-positive gate (2026-11-20)

The JSONL evaluator reports a Wilson score 95% upper bound for clean-message false-positive probability, in addition to the observed false-positive rate. A corpus with zero false positives does **not** establish a zero underlying false-positive probability. `--max-fpr-upper-95` optionally fails qualification when that upper bound exceeds the configured limit. `--min-clean` and `--min-spam` require sufficient independently labeled examples; defaults preserve existing acceptance behavior. Example: `go run ./cmd/spamgate-corpus-eval --input labeled.jsonl --min-clean 1000 --min-spam 1000 --max-fpr 0.001 --max-fpr-upper-95 0.005`.

This evaluates supplied scores and labels, not the production classifier or real mailbox outcomes. Corpus independence, class balance, ground-truth provenance, poisoning, drift and real-world false positives remain unqualified. No mail delivery behavior, daemon architecture, Postfix, Dovecot, or host configuration was changed.

Previous exact-HEAD engineering run 44840246671 failed in `TestColdRestoreDestinationRejectsCredentialIndependentInvalidTarget`: credential boundary resolution ran before invalid destination preflight. Reordered the two checks; new CI must establish regression success. Existing credential-overlap ordering tests may require reconciliation, and should not be silently weakened.

Production issues #1–#9 remain open. Beta is not qualified.