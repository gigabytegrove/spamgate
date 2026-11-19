# Native cold restore staging — 2026-11-18

Issue #8. RestoreCold verifies a signed inventory before copying, stages regular files with private permissions in the destination parent, hashes each copied file, synchronizes staged files and directories, rechecks the source, then renames into a previously absent target. It does not touch Postfix, Dovecot, systemd, or the active SpamGate directory.

This is a **cold, operator-controlled restore primitive**, not a complete disaster-recovery workflow. The operator must provide an immutable, quiesced backup, keep the HMAC key outside it, isolate the destination parent from concurrent writers, and ensure the target is not the running SpamGate data directory. A race remains between target absence check and rename; native rename may replace a concurrently created empty target on Linux. No owner/group/xattr/ACL preservation, database consistency proof, service integration, or live-host acceptance is claimed.

New regressions cover successful publication, existing-target refusal, tampered authentication, backup overlap, and symlinked parent. Source-only implementation; CI and host execution must be independently checked. The October 31 beta target has passed and all nine issue acceptance gates remain open.
