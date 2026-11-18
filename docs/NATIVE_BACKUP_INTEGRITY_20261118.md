# Native backup integrity gate — 2026-11-18

Scope: issue #8. New `internal/backupverify` provides read-only validation of a versioned file manifest before any manual restore. This is not a backup creator or a restore executor.

The validator rejects traversal, absolute paths, Windows-style paths, duplicate entries, file/directory collisions, unsupported versions, invalid sizes, invalid digests and malformed inventories. Verification requires regular files of exact declared length and SHA-256 digest, refuses symlinks in parent directories and on Linux opens the final component with O_NOFOLLOW. Verification does not change /opt/spamgate/data, Postfix, Dovecot, services, Milter ports or live mail queues.

The interface is deliberately not wired to an automated restore button: restoration requires a separately designed atomic, quiesced and rollback-capable process, with permission and ownership preservation. A manifest without a trusted signature is **not** evidence of authenticity. Manifest coverage is caller-controlled; missing files not listed in the manifest are not detected. This API does not yet enforce root descriptor-relative openat walking against concurrent path replacement. Operators must verify offline against a quiesced snapshot controlled by a trusted account.

Regression fixtures cover good backups, content corruption, missing files, final and parent symlinks, unsafe path spellings, duplicate entries, invalid digest encoding and path collisions.

Qualification status: source committed; new Go tests and go vet **not yet verified** in this run; no live restore or production-host acceptance. Issues #1–#9 remain open. The October 31 target has passed. Native foreground launcher /opt/spamgate/spamgate, spamgate-worker, /opt/spamgate/data and Milter ports 38470/38472 are unchanged.
