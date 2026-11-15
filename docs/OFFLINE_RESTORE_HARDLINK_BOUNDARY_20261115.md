# Offline restore hard-link boundary — 2026-11-15

The Linux offline restore verifier now refuses persistent files and ephemeral
runtime lock files whose inode link count is not exactly one. A checksum alone
does not establish filesystem isolation: a hard link can point at the same
inode as a file outside the restored tree, permitting external mutation after
verification. The check happens before runtime locks are exempted from the
manifest comparison.

The Linux check fails closed if the filesystem stat representation is
unavailable. The non-Linux fallback does not enforce link count; it is not
evidence of Linux production qualification.

Regression tests exercise an externally linked persistent file, an externally
linked runtime lock, and a valid ordinary restore. No production Postfix or
Dovecot configuration is changed. The target layout remains
`/opt/spamgate/spamgate`, `spamgate-worker`, `/opt/spamgate/data`,
and Milter ports 38470/38472.

This does not establish a race-free proof against privileged concurrent
filesystem mutation, nor end-to-end host backup/restore qualification. Restore
and verification remain offline operations; operators must stop all writers.
