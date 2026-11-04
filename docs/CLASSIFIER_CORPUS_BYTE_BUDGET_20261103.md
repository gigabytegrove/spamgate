# Native classifier corpus input-byte budget — 2026-11-03

Production gate: #5. The existing `--max-records` budget counts accepted labelled examples, but does not bound bytes consumed by blank lines, whitespace, or large input records. The scanner already caps a single JSONL token at 64 KiB; this change adds a separate total-input budget.

`spamgate-eval` now accepts `--max-input-bytes` (default 134217728 bytes, 128 MiB). The limit counts all input bytes, including blank lines, and is enforced alongside the existing record limit. A bounded reader permits one extra byte to distinguish an exact-size corpus from an oversized corpus. Oversized input exits with code 2 without a partial JSON report. Invalid zero, negative, or maximum-int64 byte budgets are rejected before opening the corpus.

The input budget limits reading, not all allocations: the unique-ID map still grows up to `--max-records`. The corpus remains locally supplied, and these checks do not demonstrate classifier precision, recall, representative labels, mail-host behavior, or beta qualification.

Regression coverage: exact-byte acceptance, one-byte overflow, whitespace amplification, malformed oversized input and invalid budgets. Run `go test ./cmd/spamgate-eval` and `go test ./...` on the exact commit; require CI and real mail-host evidence before qualification. No Postfix/Dovecot configuration, systemd service, or running mail server is modified.
