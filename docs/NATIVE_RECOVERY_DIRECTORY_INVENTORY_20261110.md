# Native offline recovery: directory inventory (2026-11-10)

Schema 2 snapshots record the complete sorted relative directory inventory under `directories`, including empty nested directories. Snapshot staging creates those directories before copying files. Verification refuses extra or missing directories even when the file inventory and hashes match. Restore creates the directory inventory and validates it again before atomic publication. Schema 1 archives remain readable and restorable, but schema 1 cannot prove preservation of empty directories.

The operator must stop SpamGate and verify the source is quiescent before using `--acknowledge-offline`. The tool does not stop services, modify Postfix/Dovecot, or alter live mail configuration. Its integrity checks do not establish a database-consistent backup while writers remain active. Directory modes, owners, ACLs and extended attributes are not yet preserved; the directory inventory records names only. No production-host restore qualification has been performed.

Regression coverage: nested empty directory round-trip, unexpected and missing payload directories, duplicate directory entries, and schema 1 compatibility. These tests must pass in engineering CI before treating the change as verified. All production gates #1–#9 remain open.
