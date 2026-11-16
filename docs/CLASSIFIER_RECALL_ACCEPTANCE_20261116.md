# Offline classifier recall acceptance (2026-11-16)

The native `spamgate-classifier-eval` command now supports **both** independently enforced one-sided Wilson confidence gates: `-max-fp-upper` for false positives on legitimate messages and `-min-recall` for spam detection. The latter requires `-min-spam` labeled spam examples **per tenant** (default 100); the existing `-min-clean` controls clean samples. Both use `-z-score` (default 1.6448536269514722, one-sided 95%). A failed tenant or overall result exits nonzero and emits JSON evidence.

Example (offline only): `go run ./cmd/spamgate-classifier-eval -threshold=5 -max-fp-upper=0.01 -min-clean=1000 -min-recall=0.95 -min-spam=1000 < corpus.json`.

A small sample can fail despite perfect observed recall because its Wilson lower bound is conservative. Scores are not calibrated by this tool. The corpus must come from independently labeled, representative, production-pipeline scoring; synthetic fixtures and passing unit tests are not production classifier qualification. No message disposition, mail host configuration, runtime service, tenant policy, or Milter port is changed.
