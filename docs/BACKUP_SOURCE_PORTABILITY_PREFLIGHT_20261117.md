# Native backup source identity preflight — 2026-11-17

Production gate: backup and disaster recovery (issue #8).

The native offline backup now validates the complete sorted manifest **before** closing the ZIP writer or publishing the archive. Previously `Create` deferred portable path topology rejection to its final readback `Verify` call, after the complete archive had already been written and synchronized. The new preflight fails earlier for case-insensitive duplicates and file/directory ancestor collisions that Linux permits but recovery targets may not.

Regression coverage creates real case-distinct Linux files and mixed-case file/directory conflicts, calls the public `Create` entry point, and checks that the destination archive was not published. This does not alter the existing offline worker lock, atomic publication, hashes, size limits, or restore behavior.

The permanent foreground launcher remains `/opt/spamgate/spamgate`, worker `spamgate-worker`, persistent state `/opt/spamgate/data`, and Postfix Milter ports 38470/38472. No Docker or live mail-server changes.

Qualification is incomplete until the final commit's GitHub engineering workflow and isolated Postfix/Dovecot lab pass, followed by independent real-host cold backup/restore and mail-delivery acceptance. No production host was accessed in this pass.
