# Native backup operator private-input hardening — 2026-11-19

## Scope
The native Linux `spamgate-backup-verify` operator now reads both its raw authentication key and authenticated manifest using pinned Linux descriptors. `O_NOFOLLOW` refuses a final-component symlink; `O_NONBLOCK` prevents opening a FIFO from blocking before the regular-file check. Both inputs must be private regular files with no hard-link aliases. The key is bounded to 32–4096 bytes, and the manifest to 1–16777216 bytes. The helper checks file identity, size, and modification time around the bounded read. No mail services, Postfix configuration, or persistent SpamGate data are modified.

## Corrected regression
The existing CLI test referenced an undefined `manifest` variable; it now creates a concrete manifest path. New Linux regressions cover symlink, hard-link, directory, group/world-readable, oversized, and undersized inputs. The non-Linux implementation refuses the operation.

## Evidence and limitations
GitHub commits confirm source writes only; successful compilation and test execution must be established from exact-HEAD Actions results. This is not proof of successful restore or production mail-host qualification. Parent-directory substitution by a privileged adversary, post-read changes, snapshot consistency, filesystem ownership/ACL preservation, production backup integration, and full disaster-recovery orchestration remain open. Issues #1–#9 remain production gates. Preserve `/opt/spamgate/spamgate`, `spamgate-worker`, `/opt/spamgate/data`, and Milter ports 38470/38472. Do not automatically modify the running mail server.
