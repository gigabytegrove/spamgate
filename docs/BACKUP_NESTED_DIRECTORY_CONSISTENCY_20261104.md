# Offline backup nested-directory consistency (2026-11-04)

Production gate: #8. The native Linux deployment, persistent /opt/spamgate/data and foreground launcher remain unchanged. No mail-host configuration or running services were touched.

## Root cause
The backup walker recorded and rechecked only the root directory after traversing its contents. A nested directory could be replaced, renamed, or modified after WalkDir visited it. Earlier file-level identity checks did not detect a new file added after traversal, so the published manifest could omit it.

## Correction
Record metadata for every visited directory after acquiring the offline worker lock. Before writing the manifest and publishing the archive, revalidate the pathname, inode identity, size, modification time and Linux change time of every recorded directory. Reject any changed directory and discard the temporary archive. Reject a source file named spamgate-backup-manifest.json rather than producing a duplicate ZIP member with the reserved manifest name.

## Tests added
- Stable nested directory is accepted; a replacement at its original pathname is rejected.
- A file inserted after the nested directory snapshot is rejected.
- A reserved manifest filename is rejected and no output archive is published.

## Qualification limits
These are source-level regression cases, not proof of production recovery. The directory checks are best effort and do not create an atomic snapshot. Mutations after the final validation remain possible, and the offline advisory lock only protects cooperating SpamGate writers. Real stopped-service backup/restore, filesystem fault injection, rollback, artifact provenance and host-level recovery remain outstanding. Exact-HEAD CI and Go tests must be checked before calling this change qualified.
