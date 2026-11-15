# Offline restore destination identity gate — 2026-11-15

The native backup verifier now checks that the destination directory pathname still resolves to the same directory inode after the full byte comparison and worker-lock validation. A renamed, missing, replaced, or symlink-substituted destination fails verification. The check is read-only and never changes Postfix, Dovecot, or the running mail server.

Regression cases cover stable identity, directory replacement, missing directory, and symlink substitution.

This is defense in depth, not an atomic snapshot. Privileged concurrent mutation of the directory tree can still race checks. Qualification requires a stopped worker, quiescent restore tree, restricted ancestor directories, and independently verified real-host cold restore. GitHub CI is not production-host evidence. Issues #1–#9 remain open.
