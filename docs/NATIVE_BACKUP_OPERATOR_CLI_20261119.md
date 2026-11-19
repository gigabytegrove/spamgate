# Native authenticated backup operator CLI — 2026-11-19

Issue #8 implementation: `cmd/spamgate-backup-verify` provides explicit `verify` and `restore` operations for an already quiesced, authenticated backup tree. It does not install a service, alter Postfix/Dovecot, replace /opt/spamgate/data, or generate snapshots.

Build on a host with the repository-required Go toolchain: `go build -o spamgate-backup-verify ./cmd/spamgate-backup-verify`.

Example read-only verification:
`./spamgate-backup-verify -operation verify -backup /srv/spamgate-cold-backup -manifest /srv/spamgate-manifest.json -key-file /root/spamgate-backup.key -active-data /opt/spamgate/data`

Example cold restore to a **new** directory, never active data:
`./spamgate-backup-verify -operation restore -backup /srv/spamgate-cold-backup -manifest /srv/spamgate-manifest.json -key-file /root/spamgate-backup.key -active-data /opt/spamgate/data -target /srv/spamgate-restored`

The raw authentication key must be 32–4096 bytes and have no group/other permission bits. The CLI verifies the key file identity after opening and bounds reads. It refuses a backup nested within active data, active data nested within the backup, and restore targets overlapping active data. It delegates authenticated completeness and atomic no-replace restore to backupverify. Key bytes are never passed as CLI arguments or printed.

Added regression coverage for verify/restore, nested empty directories, key permissions, active-data protection and path-prefix boundaries.

**Qualification:** GitHub commits are source evidence, not executed tests. Container checkout failed due to GitHub DNS resolution; local Go is 1.23.2 while go.mod requires 1.27.4. Final-HEAD CI must be inspected separately. No production mail host was touched. The CLI is not yet integrated into the native installer, update/rollback controller or the production backup workflow. Quiesced snapshot creation, service coordination, ownership/ACL/xattr recovery, adversarial path races, real-host restoration and all other issue #1–#9 gates remain open. No beta readiness is asserted.
