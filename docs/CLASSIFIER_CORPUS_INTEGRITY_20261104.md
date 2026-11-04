# Classifier corpus integrity gate — 2026-11-04

Production gate #5: `spamgate-eval` now accepts an optional `--corpus-sha256=<64 lowercase hexadecimal>` argument. The evaluator computes SHA-256 over the complete input file, including whitespace and trailing bytes, and refuses a mismatch with exit code 2 before emitting a JSON qualification report. The flag is optional to preserve existing evaluation workflows; it does not authenticate the person supplying the expected digest. Obtain the digest from an independently controlled adjudication pipeline, not from the same untrusted file source.

Regression coverage: matching hash, incorrect hash, malformed/uppercase hash, and appended trailing whitespace after an otherwise valid corpus. Run `go test ./cmd/spamgate-eval -count=1` and `go test ./... -count=1` on the exact commit. This pass made no changes to native service paths, Postfix, Dovecot, running mail hosts, or Milter ports.

Qualification: GitHub source writes are not equivalent to executed tests or live-mail-host acceptance. All nine production gates remain open until independent CI and host evidence establish their acceptance criteria. The October 31 beta target has passed and must not be represented as achieved.
