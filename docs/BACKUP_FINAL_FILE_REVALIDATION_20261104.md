# Backup final source-file revalidation (2026-11-04)

Production gate: #8 (offline backup/restore).

## Failure mode
Before this change, each source file was checked immediately after copying, while only directories were checked after the full traversal. A previously copied file could be replaced, removed or modified while subsequent files were being archived, leaving a manifest inconsistent with the source tree.

## Correction
`Create` records the original `os.FileInfo` for each successfully copied file. After walking the tree and verifying directory snapshots, it calls `verifyBackupCopiedFiles` to recheck pathname identity, type, size, modification time and platform-specific change time before writing the manifest and publishing the archive. Any failure prevents publication. The existing advisory offline writer lock remains mandatory.

## Tests
`internal/backup/copied_file_final_validation_test.go` tests stable files, late replacement with equal-length contents, removal and append. Run `go test ./internal/backup -count=1` and `go test ./... -count=1` at the exact commit.

## Limits
This is best-effort filesystem consistency detection, not a point-in-time snapshot. A noncooperating writer can still mutate files after final validation. The lock only protects cooperating SpamGate processes. This change does not qualify backup/restore on a real mail host or establish disaster-recovery readiness. Do not modify a running mail server automatically.
