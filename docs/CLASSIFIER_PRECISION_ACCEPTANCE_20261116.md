# Classifier precision qualification (2026-11-16)

The offline `spamgate-classifier-eval` command supports `-min-precision` (0..1) and `-min-predicted-spam` (positive integer, default 100). It applies a one-sided Wilson lower confidence bound to the true-positive share of predicted spam, both overall and for every tenant. It may be combined with `-min-recall` and `-max-fp-upper`; every enabled gate must pass. Rejection emits JSON evidence and a nonzero exit status. No running mail policy, Postfix service, or persistent data is modified.

Example: `spamgate-classifier-eval -min-precision=0.95 -min-predicted-spam=100 -min-recall=0.90 -min-spam=100 -max-fp-upper=0.01 -min-clean=100 < labeled-corpus.json`

A tenant with no predicted spam fails the minimum sample gate even when the configured minimum precision is zero. An aggregate pass cannot mask a failing tenant. The minimum sample count and confidence bound are deliberately independent: a low sample count fails even if the observed precision is 100%.

**Qualification limits:** Precision is sensitive to the spam prevalence of the evaluation corpus and is not a substitute for the false-positive rate among legitimate messages. The labeled corpus must be independently reviewed, representative, and scored by the production classifier. This tool does not prove MIME/phishing coverage, mail delivery, live tenant enforcement, or beta readiness. GitHub Actions and real-host tests must be checked separately.
