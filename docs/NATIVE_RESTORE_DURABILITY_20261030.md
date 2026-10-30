# Native offline restore durability and archive validation — 2026-10-30

This change advances production gate #8 without declaring disaster recovery complete.

- Restored files are individually written, hashed and fsynced, then every staged directory is fsynced deepest-first on Linux before the atomic no-replace publication. The destination parent is fsynced by the existing publisher.
- Archive verification rejects a file whose name is also a directory prefix of another ZIP entry. This prevents conflicting restore topology before any extraction.
- ZIP entry totals are checked using subtraction before addition, preventing unsigned integer overflow in the aggregate size limit.
- Control-character filenames are refused to avoid ambiguous recovery paths and logs.
- The archive SHA-256 manifest detects accidental corruption but is **not an authenticity signature**. An attacker able to replace the entire ZIP and manifest can forge matching hashes.
- No running SpamGate process, Postfix configuration, or Dovecot configuration is changed.

## Operator procedure

Stop the native SpamGate service and confirm the worker no longer holds its data lock before backup. Create an archive outside the data tree:

```bash
/opt/spamgate/spamgate-worker -data /opt/spamgate/data -backup-file /secure-backups/spamgate-offline.zip
/opt/spamgate/spamgate-worker -verify-backup /secure-backups/spamgate-offline.zip
```

For a recovery rehearsal, restore into a **nonexistent** sibling directory, inspect its contents, and only then plan an explicitly authorized cutover:

```bash
/opt/spamgate/spamgate-worker -data /opt/spamgate/data-restored -restore-backup /secure-backups/spamgate-offline.zip
```

## Remaining acceptance gates

A filesystem-level power-loss/fault-injection run, actual cold restore on the intended host, retained queue replay qualification, backup encryption/key management, and live native update/rollback are **unverified**. This does not qualify long-term beta.
