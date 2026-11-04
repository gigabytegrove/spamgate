# Backup source-root identity validation — 2026-11-04

## Defect
The offline backup walked the source data directory without rechecking that its root pathname still named the original directory after traversal. A concurrent rename/replacement could leave a valid-looking archive from a detached source tree. Per-file checks alone cannot prove the root identity.

## Change
The backup now re-stats the root pathname after WalkDir and before manifest publication. The existing path identity validator now accepts directories as well as regular files by comparing file type, inode identity, size, mtime, and platform change-time. A replacement, unlink, symlink, or detectable metadata mutation fails the backup without publishing an archive. The baseline root metadata is captured after acquiring the offline lock, because first-time lock inode creation may change the directory metadata.

## Regression coverage
source_root_identity_test.go covers stable directory, replaced directory, and symlink replacement. These tests were committed but not executed in this pass; exact-HEAD CI has not been observed passing.

## Limitations
This is best-effort filesystem race detection, not an atomic snapshot. A malicious actor with concurrent write access can still race the final check. Operators must stop SpamGate and hold the offline lock during backup. Real Postfix/Dovecot qualification, restore drills, crash recovery, and all nine production gates remain open. No production mail server was modified.
