# Native cold restore: descriptor-relative publication (2026-11-19)

## Scope

Linux amd64/arm64 cold-restore publication now opens the destination parent as a directory descriptor with O_NOFOLLOW and O_CLOEXEC, checks its inode/device against the named directory, and performs renameat2(RENAME_NOREPLACE) using the pinned descriptor for both operands. The source staging directory and target must have the same parent. No fallback to replacing rename is allowed. The parent directory is fsynced through the pinned descriptor after successful publication.

## Regression coverage

The Linux publication tests cover successful publication, refusal to replace an existing directory with preserved sentinel data, cross-parent refusal, and symlink-parent refusal.

## Architecture and safety

The locked foreground launcher remains /opt/spamgate/spamgate; the worker is spamgate-worker; persistent state is /opt/spamgate/data; Postfix Milter ports are 38470/38472. No Docker substitution or live Postfix/Dovecot changes were made.

## Unresolved risks and acceptance

This is not a complete adversarial path-race solution: staging directory creation, copy, cleanup, and the backup source still use pathnames and must be reviewed for directory replacement and concurrent modification. A rename of the parent after its descriptor is pinned could publish into the original now-unlinked/reparented directory; descriptor anchoring prevents redirection to a different directory, but does not guarantee that the named destination remains reachable. The parent-directory fsync can fail after publication, so the API may return an error even though the directory has already been published; callers must inspect the destination before retrying. Cold restore still requires owner/ACL/xattr preservation, database consistency, full service recovery, and real host qualification.

This change does not close issues #1-#9 or establish beta readiness. Final-head CI and isolated laboratory results must be inspected separately; production-host evidence remains mandatory.
