# Native recovery path-alias and mount traversal guard — 2026-11-10

This change is part of issue #8 and does **not** qualify production recovery.

The read-only preflight rejects CLI data paths containing literal `.` or `..` components before `pathlib.Path` can normalize them. This prevents a misleading inspection of an aliased path when an operator intended a different directory. The program also refuses a nested mount identified by Linux `/proc/self/mountinfo` and now prunes that directory from traversal rather than reading through it. Bind mounts sharing the same device number remain detected by mountinfo.

The new regression cases check both lexical aliases and confirm that an identified nested mount is not traversed. They are invoked through the existing engineering qualification workflow (`scripts/test-spamgate-recovery-preflight.py`).

Limitations: the scan is not atomic and cannot eliminate concurrent mount changes or path replacement. It does not verify Postfix/Dovecot state, quiesce databases, preserve ACLs or UID/GID, perform restore, or qualify a live mail host. A clean preflight is a prerequisite only. The native foreground launcher, worker, persistent data path, and Milter ports remain unchanged. No mail server is reconfigured or stopped.
