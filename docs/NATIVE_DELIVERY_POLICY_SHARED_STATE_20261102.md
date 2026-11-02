# Native delivery-policy cross-process consistency — 2026-11-02

**Status:** implementation and regression coverage, not production-host qualification. Applies to gates #4 and #6.

The native Linux Milter policy evaluator now takes a private, persistent `.delivery-policy.lock` advisory lock around the entire read/modify/atomic-write cycle. It reloads the strict bounded `delivery-policy.json` state while holding that lock; concurrent native SpamGate workers sharing one data directory cannot each enforce against a stale startup snapshot and overwrite the other's rate counters or greylist entries. The lock file is not deleted during normal operation. A symlink, changed inode, unowned file, non-0600 file, unsafe parent directory, or lock timeout refuses evaluation rather than bypassing enforcement.

The directory entry is fsynced after publishing the updated state. A running worker refuses ambiguous or corrupt state that appears after startup and refuses a previously published state file disappearing; it preserves forensic evidence instead of silently resetting policy. A missing file on a first-ever evaluation remains a valid empty bootstrap.

Tests exercise two separately opened stores, concurrent policy decisions, stale counter refresh, post-start corruption, deletion, and exact persisted counts. **Limitations:** native Linux `flock` coordination is local-filesystem only; non-Linux builds have process-local locking. Remote/distributed filesystems, actual power loss, disk-full injection, multi-host policy sharing, and production ISPConfig mail flow remain unqualified. Existing non-Linux deployments must not share a data directory between processes. The policy is fail-closed on storage errors; operators must preserve evidence and repair the state rather than deleting counters.

Architecture remains the foreground `/opt/spamgate/spamgate` launcher, `spamgate-worker`, `/opt/spamgate/data`, and Postfix Milter ports 38470/38472. No mail-server configuration is modified.
