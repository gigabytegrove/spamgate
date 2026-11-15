# Native Linux restore verifier: ancestor symlink refusal

The offline restored-tree verifier now opens every ancestor directory using descriptor-relative `openat` with `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` and opens the leaf with `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`. This prevents a substituted ancestor symlink from redirecting a restored file read outside the selected directory tree. Directory descriptors are closed after use. The existing inode, hard-link, size, timestamp and SHA-256 checks remain in place.

This does **not** prove atomic directory-tree identity across concurrent privileged renames. An attacker with permission to rename directory entries may still race directory traversal without introducing symlinks. Verification requires the restored tree to be quiescent and access controlled. No live mail host was modified or qualified by this change.

Regression tests cover ancestor and leaf symlink refusal. The native Linux target remains `/opt/spamgate/spamgate`, `spamgate-worker`, `/opt/spamgate/data`, and Milter ports 38470/38472. This is a narrow backup/restore security improvement, not a declaration of beta readiness.
