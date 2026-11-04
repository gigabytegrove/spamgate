# Linux corpus change-time verification — 2026-11-04

## Defect
The evaluator previously checked inode identity, size and mtime. A same-length rewrite followed by restoring the original mtime could evade those checks.

## Correction
On the native Linux target, descriptor and pathname stability checks additionally compare kernel inode ctime (seconds and nanoseconds). A detected change is fatal before qualification JSON is written. Non-Linux builds retain the previous behavior. A Linux regression rewrites a same-length corpus, restores mtime and verifies both guards reject it.

## Limitations
ctime is not a cryptographic guarantee of immutability and cannot prevent every concurrent filesystem race or privileged tampering. Use an independently recorded `--corpus-sha256` and immutable corpus snapshot. This change does not qualify the live Postfix/Dovecot mail path.

## Verification
Run `go test ./cmd/spamgate-eval -count=1` on Linux and `go test ./... -count=1`; inspect exact-commit CI. Committed tests are not evidence of execution.
