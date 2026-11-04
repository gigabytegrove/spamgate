# Classifier corpus filesystem stability — 2026-11-04

Production gate: #5. Status: implementation committed, CI and production-host qualification not yet verified.

The standalone `spamgate-eval` command now accepts only an existing regular corpus file. It rejects symlinks, directories, FIFOs and devices before attempting to parse or hash. The opened file must refer to the same filesystem object inspected before opening. After parsing and optional SHA-256 checking, it rechecks the open descriptor's identity, size and modification time; a detected mutation fails with exit status 2 and no JSON qualification report.

These checks prevent accidental evaluation of live streams and catch common concurrent corpus edits. They are **not** an atomic snapshot: an adversary with write access may change bytes while preserving timestamps and size. For independent qualification, use a read-only corpus snapshot, strict unique IDs, `--corpus-sha256`, and independently adjudicated labels. Never use the tool's report alone to claim real Postfix/Dovecot qualification.

Changed files: `cmd/spamgate-eval/main.go`, `cmd/spamgate-eval/corpus_stability.go`, `cmd/spamgate-eval/corpus_stability_test.go`.

Suggested verification: `go test ./cmd/spamgate-eval -count=1`; `go test -race ./cmd/spamgate-eval -count=1`; `go vet ./cmd/spamgate-eval`. Run end-to-end on a disposable host before treating this as qualified. No mail-server settings, services, Milter ports, native launcher, worker or persistent data layout were changed.
