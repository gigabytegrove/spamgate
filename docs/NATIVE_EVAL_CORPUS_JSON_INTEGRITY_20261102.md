# SpamGate classifier evaluation JSON integrity — 2026-11-02

## Scope

The native `spamgate-eval` command is a **read-only, operator-invoked** statistical evaluator. This change addresses issue #5's false-positive measurement integrity and issue #6's privacy-safe diagnostics. It does not modify the mail host, alter classification scores, change policy, submit mail, or qualify a production installation.

Previously the Go JSON decoder could silently use the last of duplicate `label` or `action` keys. Case-insensitive field aliases, invalid UTF-8 replacement and JSON null-to-empty string coercion also allowed misleading corpus records. These inputs can invalidate an otherwise correctly calculated confusion matrix.

Every JSONL record is now validated before any count is incremented:

- Exactly one root object, no duplicate keys or Unicode/case-folded aliases, no unpaired Unicode surrogate escapes, no trailing JSON values and valid UTF-8.
- Exact schema keys `label`, `action`, `cohort`, `id`; case variants and additional fields (including message metadata) are refused.
- Each field must be a JSON string, not null, number, boolean, array or object. Label/action are mandatory.
- Existing 64 KiB per-record scanner budget and SHA-256 duplicate-ID checks remain in force.
- Parser errors do not echo untrusted field values or private message content. No partial report is emitted for a malformed corpus.

Run `go test -count=1 ./cmd/spamgate-eval ./internal/spooljson` to exercise malicious and legacy fixtures. Engineering CI also executes the full Go/race suite and compiles the native evaluator.

## Qualification boundary

The historical two-field `label`/`action` format is still accepted for backward compatibility. **For beta qualification**, use `--require-unique-ids --require-cohorts` with independent adjudication and the documented sample-size and Wilson-bound thresholds. Passing on an artificial or nonrepresentative corpus does not establish classifier accuracy on production traffic. These tests do not verify the authenticity of an operator-supplied verdict, SMTP/Dovecot delivery, disk-failure recovery, or live false-positive rates.

The permanent `/opt/spamgate/spamgate` foreground launcher, `spamgate-worker`, `/opt/spamgate/data`, and Postfix Milter ports 38470/38472 are unchanged. No Docker replacement or mail-server reconfiguration is introduced.
