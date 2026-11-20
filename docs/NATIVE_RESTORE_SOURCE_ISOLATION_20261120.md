# Cold restore source isolation — 2026-11-20

## Scope

The native `spamgate-backup-verify -operation restore` CLI now refuses a
restore destination that is the authenticated backup root, a descendant of it,
or an ancestor containing it. Both paths are normalized using the existing
symlink-aware ancestor resolver, including when the destination does not yet
exist. This protects the recovery source from accidental destructive writes.

The source boundary check runs after the existing active-data backup boundary
and before authentication-key/manifest reads and any restore writes. Verification
mode remains unchanged. No mail services are restarted or reconfigured.

## Regression coverage

`go test ./cmd/spamgate-backup-verify` includes same-directory,
descendant, missing nested descendant, ancestor, symlink alias and independent
sibling path cases, plus CLI refusal before missing credential reads.

## Qualification limits

These tests are not evidence of a real production-host cold restore. The
preflight does not eliminate concurrent directory replacement or symlink races
between validation and restore creation. Real host backup/restore, filesystem
race resistance, update/rollback, and all other issues #1–#9 remain open.
Do not close issue #8 or declare beta readiness based on this change.
