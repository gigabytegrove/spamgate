# Native recovery traversal completeness — 2026-11-10

## Correctness change
Offline snapshot and verification now fail closed when Python's os.walk reports an unreadable or otherwise inaccessible subtree. Without an onerror callback, os.walk can silently omit a directory, yielding an incomplete snapshot or an incomplete verification inventory. Both file and directory inventory paths now raise SnapshotError on traversal errors.

## Regression coverage
The Python regression suite injects a deterministic traversal error into both inventory paths and checks refusal. A separate POSIX FIFO test verifies that snapshot creation rejects a special file without publishing a backup. The existing engineering workflow invokes scripts/test-spamgate-offline-data.py directly.

## Qualification limitations
These checks do not guarantee database-consistent snapshots, preserve UID/GID/ACLs, prevent concurrent path substitution, or establish cold restore on a production host. Operators must stop SpamGate before snapshot/restore; --acknowledge-offline does not detect service state. The locked native launcher, worker, persistent data directory and Milter ports are unchanged. No mail-server configuration is modified.
