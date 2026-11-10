# Native offline recovery: directory permissions (schema v3) — 2026-11-10

Issue #8 remains open and is **not production qualified**.

The offline snapshot manifest now records POSIX permission bits for every non-root directory in `directory_modes` and validates those bits during verification and staged restore. Snapshot creation rechecks source directory permissions before publication. Directory modes are applied deepest-first after copying files so restricted directories do not prevent initial staging.

Schema v1 and v2 snapshots remain readable and restorable; their directory permissions cannot be reconstructed because the older manifests did not record them. Schema v3 requires exact directory inventory and exact mode keys, with integer modes from 0000 through 0777. The snapshot payload and restored stage are checked before publication. The new regressions cover mode roundtrips, payload tampering, invalid manifest modes, and schema v2 compatibility; existing schema v1 compatibility remains covered.

Safety boundaries: operator acknowledgement does not detect a running service or quiesce a database. This change does **not** preserve UID/GID, POSIX ACLs, extended attributes, SELinux labels, root directory mode, or atomic consistency across a running database. Highly restrictive source modes may require privileged offline operation; no privilege escalation is performed. Snapshot and restore refuse overwrite. No mail host is automatically modified.

Verification required: run `python3 scripts/test-spamgate-offline-data.py -v` and inspect exact-commit engineering CI. Then perform an authorized cold restore on an isolated Linux host with representative filesystem permissions and database state. No production-host acceptance is claimed.
