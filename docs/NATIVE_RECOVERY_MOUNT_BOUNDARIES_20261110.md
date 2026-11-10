# Native recovery preflight: Linux mount boundary qualification

The read-only preflight now inspects `/proc/self/mountinfo` and refuses nested mounts, including bind mounts on the same filesystem device. Device-number checks alone cannot detect these. Mount-table read or parse failures fail closed. The root itself may be a mount point; child mount points are refused.

The preflight also rechecks the data-root identity and timestamps after traversal. This catches some concurrent mutations, but is **not** a filesystem snapshot, transaction, inode-pinned traversal, or proof of quiescence. Operators must stop writers and coordinate database checkpoints before offline backup; no services are stopped automatically.

Regression coverage includes same-device bind-mount records, escaped mount paths, unavailable mount metadata, and nested-mount refusal. CI executes the native preflight tests on Linux. No production Postfix/Dovecot server is touched, and real-host mount behavior still requires independent qualification.

Locked runtime paths and ports remain unchanged: `/opt/spamgate/spamgate`, `spamgate-worker`, `/opt/spamgate/data`, 38470 and 38472.
