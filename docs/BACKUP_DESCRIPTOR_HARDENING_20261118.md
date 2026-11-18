# Backup verification descriptor hardening — 2026-11-18

## Change
Linux verification now opens the backup root as a directory descriptor and walks each child with `openat(O_DIRECTORY|O_NOFOLLOW)`. The final file is opened with `O_NOFOLLOW|O_NONBLOCK` and validated by `fstat` on the same descriptor that is hashed. This prevents replacing a checked child directory or final file with a symlink between a path-based check and opening it. FIFO and nonregular objects are rejected without blocking. Non-Linux platforms fail closed.

## Regression
`internal/backupverify/open_linux_test.go` exercises parent and final symlinks, directory targets, FIFO targets, and an inode pinned across a pathname replacement. Existing manifest and checksum tests remain applicable.

## Boundaries and remaining production gates
The caller must supply a trusted backup root; ancestor directories leading to that root are not pinned. A malicious actor with write access to the backup tree can mutate an already opened regular inode during hashing; an authenticated manifest, exclusive snapshot or immutable backup staging, full inventory completeness, and atomic cold restore remain required. This code performs verification only and never restores data or changes Postfix/Dovecot.

Issues #1–#9 remain open. Real-host disposition, durable delivery, SMTP/auth compliance, classifier false-positive acceptance, tenant enforcement, diagnostics, browser UI, backup/restore, and native update/rollback still require end-to-end qualification. No production mail host was touched.

## Evidence
Source changes committed directly to main. Final-HEAD CI and local tests must be inspected separately; no passing test or real mail-host qualification is asserted by this document.
