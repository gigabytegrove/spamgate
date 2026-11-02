# Native delivery-policy cross-process consistency — 2026-11-02

**Status:** implementation and regression coverage, not production-host qualification. Applies to gates #4 and #6.

The native Linux Milter policy evaluator now takes a private, persistent `.delivery-policy.lock` advisory lock around the entire read/modify/atomic-write cycle. It reloads the strict bounded `delivery-policy.json` state while holding that lock; concurrent native SpamGate workers sharing one data directory cannot each enforce against a stale startup snapshot and overwrite the other's rate counters or greylist entries. The lock file is not deleted during normal operation. A symlink, changed inode, unowned file, non-0600 file, unsafe parent directory, or lock timeout refuses evaluation rather than bypassing enforcement.

The directory entry is fsynced after publishing the updated state. A running worker refuses ambiguous or corrupt state that appears after startup and refuses a previously published state file disappearing; it preserves forensic evidence instead of silently resetting policy. A missing file on a first-ever evaluation remains a valid empty bootstrap.

Tests exercise two separately opened stores, concurrent policy decisions, stale counter refresh, post-start corruption, deletion, and exact persisted counts. **Limitations:** native Linux `flock` coordination is local-filesystem only; non-Linux builds have process-local locking. Remote/distributed filesystems, actual power loss, disk-full injection, multi-host policy sharing, and production ISPConfig mail flow remain unqualified. Existing non-Linux deployments must not share a data directory between processes. The policy is fail-closed on storage errors; operators must preserve evidence and repair the state rather than deleting counters.

Architecture remains the foreground `/opt/spamgate/spamgate` launcher, `spamgate-worker`, `/opt/spamgate/data`, and Postfix Milter ports 38470/38472. No mail-server configuration is modified.

## Permanent first-publication evidence (additional hardening)

The first successful policy update now durably publishes `.delivery-policy.initialized` (0600, fixed versioned contents) **before** writing `delivery-policy.json`. A process that started before another worker's first write, or a process restarted after deletion of the state file, now refuses to reset counters when this marker remains. The marker is verified on startup and every policy decision; symlinks, changed inodes, unexpected contents and permissive modes refuse evaluation. Legacy state files without a marker acquire one at their next policy update, without rewriting their existing counters first.

The marker and state file form a single recovery set. Backups and restores must retain both. If the marker is present and the state file is absent (including an interrupted first write), startup deliberately fails closed. Preserve both files and investigate the filesystem; do not remove the marker to restore service. This does not provide cryptographic tamper protection against a process with write access to the data directory, and cannot retrospectively prove a legacy state file was deleted before the first upgraded write. Actual power-loss, disk-full and ISPConfig host qualification remain outstanding.
