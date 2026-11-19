# Cold restore atomic publication — 2026-11-18

Issue #8. Native Linux only. The cold restore staging implementation previously used os.Rename after a target-existence check, allowing another process to create the destination between check and rename. A directory rename can replace an empty destination directory.

RestoreCold now publishes via Linux renameat2(RENAME_NOREPLACE), which atomically refuses an existing destination (EEXIST). Linux amd64 and arm64 have explicit syscall numbers; unsupported Linux architectures and non-Linux builds fail closed. ENOSYS/EINVAL/unsupported filesystem failures do not fall back to an unsafe rename. Staging remains private and cleaned up on error.

Regression source exercises successful publication and pre-existing destination preservation, including sentinel contents and retained staging directory. These are tests of the publication primitive, not proof of complete production recovery.

Verification boundaries: GitHub commits created and branch files inspected. Local checkout is blocked by GitHub DNS resolution; installed Go 1.23.2 cannot build the repository requiring Go 1.27.4. New regression execution and final-HEAD CI are unverified. No production Postfix, Dovecot, systemd, data directory, or mail queue was touched.

Remaining: no descriptor-pinned destination parent (a privileged adversary could replace path components), no atomic snapshot creation, no live-data consistency/ownership/ACL restoration, no production cold-restore evidence, and no native update/rollback acceptance. All issues #1–#9 remain open.