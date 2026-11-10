# Native offline data snapshot and restore (unqualified recovery building block)

This standalone tool is for the locked native Linux layout. It does **not** change the permanent foreground launcher `/opt/spamgate/spamgate`, the `spamgate-worker` process, persistent data directory `/opt/spamgate/data`, Postfix, Dovecot, or Milter ports 38470/38472.

**Critical:** Stop SpamGate's launcher and worker using the site's existing service-management procedure and verify they are stopped **before** snapshot or restore. The required `--acknowledge-offline` flag is an operator assertion, not automatic verification. Do not use on live or concurrently modified data. No mail-host configuration changes are performed.

## Snapshot and independent verification

With SpamGate fully stopped and the backup parent already created with restricted permissions:

```sh
python3 scripts/spamgate-offline-data.py snapshot --source /opt/spamgate/data --target /secure/offhost-backups/spamgate-data-20261110 --acknowledge-offline
python3 scripts/spamgate-offline-data.py verify --source /secure/offhost-backups/spamgate-data-20261110
```

The target must not exist. Snapshot data is copied into a private temporary directory, per-file SHA-256 and sizes are recorded in `manifest.json`, all files are reverified, and the staged directory is renamed into place. The tool refuses symlinks, hardlinked files, nonregular files, changed source files, extra or missing snapshot files, duplicate manifest paths and JSON keys, and checksum mismatches. It bounds file count and total size. It never deletes an existing backup.

## Restore to a **new, absent** directory

With SpamGate stopped, use a new path for a rehearsal. This is intentionally not an in-place overwrite.

```sh
python3 scripts/spamgate-offline-data.py restore --source /secure/offhost-backups/spamgate-data-20261110 --target /opt/spamgate/data-restored --acknowledge-offline
```

Inspect the restored data, ownership and permissions before any operator-controlled cutover. This tool preserves file mode bits, but does **not** preserve UID/GID ownership, ACLs, extended attributes, empty directories, or guarantee a consistent snapshot of a running database. It does not perform a launcher restart, migration, swap, update, rollback, or mail-host reconfiguration. File metadata and content may include private email and credentials; store snapshots with restricted access and encryption appropriate to the host.

## Qualification boundaries

This implementation is a standalone, offline recovery primitive, **not** a complete disaster recovery or production backup solution. It has no service-stop integration, database checkpoint coordination, encryption, signing, incremental backups, remote retention, automated rollback or real-host restore certification. Those remain open under issue #8. The rest of issues #1–#9 remain open. Run `python3 scripts/test-spamgate-offline-data.py -v` for hermetic tests; the main engineering workflow also invokes this suite. No successful test result should be inferred from a commit alone.
