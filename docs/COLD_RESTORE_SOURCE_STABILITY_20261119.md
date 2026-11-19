# Native cold restore source-stability gate — 2026-11-19

## Scope

The standalone `internal/backupverify.RestoreCold` path now obtains file metadata from the opened source descriptor immediately before and after copying each authenticated file. Publication is refused if inode identity, file type, size, or modification timestamp changes. The SHA-256 digest and copied byte count remain mandatory. Regression tests cover stable sources, inode replacement, size mutation, and timestamp mutation.

This work does not alter the established foreground launcher at `/opt/spamgate/spamgate`, worker `spamgate-worker`, persistent data `/opt/spamgate/data`, or Milter ports 38470 and 38472. It does not configure or restart Postfix or Dovecot.

## Qualification limits

This is not a consistent snapshot: a privileged concurrent writer can modify a file and restore its metadata, or mutate the tree between checks. The staging directory and cleanup still need adversarial pathname-race review. The separate production `internal/backup` workflow has not been integrated with `internal/backupverify`; this package alone must not be described as a complete native backup/restore feature.

Source changes: `cold_restore.go`, `copy_stability.go`, `copy_stability_test.go`. Regression tests are present, but their execution must be established from exact-HEAD CI before claiming success. A successful isolated Postfix/Dovecot lab is not production-host acceptance.

## Open gates

Issues #1–#9 remain subject to their individual production acceptance criteria, including real mail disposition, queue durability, SMTP compliance, classifier accuracy and false positives, tenant isolation, diagnostics, browser workflows, cold restore, and native update/rollback. October 31, 2026 has passed; beta qualification is not established.
