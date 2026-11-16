# Offline classifier acceptance measurements

The `spamgate-classifier-eval` command accepts a JSON array of labeled samples on standard input and emits deterministic per-tenant and overall confusion matrices. Each sample has a unique `id`, `tenant`, boolean `spam` ground truth and finite numeric `score`. The threshold defaults to 5 and uses `score >= threshold` as the positive decision.

Example: `go run ./cmd/spamgate-classifier-eval -threshold 5 < corpus.json`

The tool is deliberately read-only, performs no SMTP calls, and never changes active classifier thresholds. It refuses duplicate sample identifiers, missing tenants, malformed JSON and nonfinite values. Input is bounded to 32 MiB. Zero-denominator rates are reported as zero; operators must inspect class counts before interpreting them. Reported precision, recall and false-positive rate describe the supplied labeled corpus only.

**Not acceptance evidence:** No representative independently labeled clean/spam corpus has been evaluated in this change. The tool does not validate the production classifier's score generation, MIME/archive detection, calibration, poisoning defenses, or real mail-host false-positive rate. GitHub issue #5 remains open.
