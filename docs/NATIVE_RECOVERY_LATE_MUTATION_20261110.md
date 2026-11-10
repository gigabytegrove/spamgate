# Offline snapshot late-mutation verification — 2026-11-10

Issue: #8 (native recovery). This change does not qualify production restore.

The offline snapshot implementation previously validated each file while copying and checked directory metadata before publication. A same-size rewrite of an already-copied source file could occur after its per-file check without changing the containing directory's mtime. The resulting snapshot could be internally checksum-valid but not represent the source state at publication.

Before publishing, the snapshot now reopens and hashes every source file and compares size, SHA-256 and POSIX mode with its copied manifest entry. The existing file descriptor identity checks detect concurrent changes during each read. This adds a second complete read of the source, so operators must budget approximately twice the source read I/O plus snapshot writes. On mismatch the staging directory is removed and the requested snapshot target is not published.

Manifest schema validation now rejects boolean JSON schema values rather than treating true as integer 1 (Python bool is an int subclass).

Regression tests cover post-copy mutation and boolean-schema rejection. Engineering CI already executes scripts/test-spamgate-offline-data.py explicitly.

Limitations: A rewrite after the final read can still race publication; a file may be modified and restored to identical bytes; there is no transactional filesystem/SQLite consistency guarantee. This utility must be used with SpamGate fully stopped and with host-level cold restore verification. UID/GID, ACLs, xattrs, mount boundaries and database consistency remain separate gates. No Postfix or Dovecot settings are changed.