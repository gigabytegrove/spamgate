# Native backup authentication-key hardlink isolation — 2026-11-20

## Scope
Issue #8, native Linux backup verification and cold restore. The existing path checks resolved symlinks but did not detect hard links: a backup inventory entry could share the same inode as an authentication key located outside the backup directory. The verifier could then read the key through a second pathname inside the backup.

## Changes
- Require the authentication key to be a regular file with exactly one hard link on Linux, using the native inode link count.
- Reject an authentication key and manifest that are different pathnames to the same inode on every supported platform.
- Preserve the immutable /opt/spamgate/data protection and existing active-data and backup isolation.
- Add regression cases for hardlinked key/manifest, hardlinked key within the backup, and distinct files.
- Retain Windows compilation with a non-Linux fallback. Cold restore remains Linux-only.

## Verification boundary
GitHub commits were published through the GitHub API. The local runner cannot resolve github.com to clone the complete repository; Go 1.23.2 is available locally while go.mod requires Go 1.27.4. Therefore no full repository test pass or production-host behavior is claimed here. GitHub Actions results must be checked for the final commit; an empty commit-status response is not a pass.

## Remaining security and operational gates
The path preflight and file open are not an atomic operation; a privileged concurrent actor can change a path after validation. Harden with descriptor-relative openat2/RESOLVE_* on Linux or equivalent and validate opened file descriptors. A real cold backup, restore, checksum verification, restart and rollback on an isolated native systemd installation remain required. The mail server must not be changed automatically. All issues #1-#9 remain open until independent end-to-end acceptance.
