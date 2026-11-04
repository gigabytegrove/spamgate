# Classifier corpus descriptor race hardening — 2026-11-04

## Root cause
The evaluator checked Lstat before os.Open. A filesystem adversary could swap the regular-file path for a symlink or FIFO between those operations. The subsequent descriptor identity check would detect a changed inode, but opening a FIFO could block indefinitely before that check.

## Correction
Linux uses a single open syscall with O_NOFOLLOW, O_NONBLOCK and O_CLOEXEC. Existing post-open regular-file and inode identity checks remain mandatory. Other platforms retain their existing opening and identity checks. Linux tests cover a symlink to a regular file, a FIFO without a writer, and successful reading of a regular file.

## Verification and limits
Run `go test ./cmd/spamgate-eval -count=1` and `go test ./... -count=1`; inspect exact-HEAD CI. This prevents symlink-following and blocking FIFO opens but does not make a mutable corpus immutable or prove production mail-path behavior. Independent SHA-256 verification and snapshotting remain required.
