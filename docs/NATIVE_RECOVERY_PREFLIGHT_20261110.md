# Native recovery preflight (2026-11-10)

The read-only `scripts/spamgate-recovery-preflight.py` checks a native SpamGate data directory before an explicitly offline snapshot. By default it inspects `/opt/spamgate/data`; use `--data /absolute/path` to inspect another directory. The output is JSON with `safe_for_offline_snapshot` and an array of findings. Exit status 0 means no detected unsafe filesystem entries; 2 means the check refused the tree.

It rejects missing or symlinked roots, relative paths, symlinks within the tree, multiply linked regular files and special files such as FIFOs. It is intentionally read-only and never starts or stops SpamGate, Postfix, or Dovecot. It does not validate quiescence, database consistency, UID/GID/ACL metadata, mounted filesystem boundaries, concurrent path substitution or mail delivery correctness. Passing preflight is **not** permission to take a live backup.

The regression suite is `python3 scripts/test-spamgate-recovery-preflight.py -v` and is wired into engineering qualification. Do not close issue #8 until an independent native-host cold backup/restore and update/rollback are qualified. All production issues #1–#9 remain open.
