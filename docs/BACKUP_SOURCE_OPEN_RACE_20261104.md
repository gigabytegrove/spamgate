# Offline backup: Linux source-open race hardening (2026-11-04)

Production gate: #8. This change protects the native Linux cold-backup source traversal from a time-of-check/time-of-use race. Previously WalkDir/Lstat validated a regular file, then os.Open followed the pathname; a concurrent symlink swap could open another file and a FIFO swap could block indefinitely. The subsequent f.Stat identity check could reject an opened wrong inode but could not prevent blocking during open.

Linux now uses O_NOFOLLOW, O_NONBLOCK, O_CLOEXEC and O_NOCTTY. The existing f.Stat regular-file and os.SameFile checks remain mandatory. The fallback on non-Linux platforms retains the old open behavior and is not claimed hardened.

Tests: go test ./internal/backup -run 'TestBackupSourceOpen' -count=1; go test ./internal/backup -count=1; go test ./... . Actual CI and live-host results must be reported separately.

Limitations: no guarantee against concurrent mutation of file contents; offline lock is still required. This does not qualify a production backup/restore or running mail host, nor does it authorize changing Postfix, Dovecot, or SpamGate services.
