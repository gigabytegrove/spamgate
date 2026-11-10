# Native offline recovery: permission integrity gate (2026-11-10)

The offline snapshot utility now validates payload file permission bits against the manifest during verification and before restore. Changing a payload file's mode without changing its bytes is a failed verification, not a valid recovery artifact. Snapshot also compares source file identity and metadata after copying against its initial inventory, rejecting detected source mode or timestamp changes.

## Operator boundaries

The utility is an offline data copy, not an online consistent backup. Stop SpamGate and its worker using the established host service procedure before using the `--acknowledge-offline` flag. This flag is an operator assertion, not service-state detection. Never assume that a successful snapshot proves a live database-consistent point in time.

The snapshot format records regular file bytes, SHA-256 and POSIX permission bits only. It does **not** preserve UID/GID, ACLs, extended attributes, SELinux labels, directory modes or timestamps. Reassign ownership and any security labels under a controlled offline restore procedure before starting the application. It does not alter Postfix, Dovecot, mail queues or service configuration.

## Validation

`python3 -m unittest discover -s scripts -p 'test-spamgate-offline-data.py' -v`

New regression coverage includes changed payload mode, changed manifest mode and successful permission-mode roundtrip. Real mail-host restore, service coordination, database consistency, ownership and ACL restoration, rollback and end-to-end recovery remain **unqualified**. No production server is changed by these source commits.
