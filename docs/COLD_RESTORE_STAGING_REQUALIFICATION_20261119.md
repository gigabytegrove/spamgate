# Cold restore staged-inventory requalification — 2026-11-19

Scope: issue #8, native Linux only. The locked launcher, worker, data root and Postfix Milter ports remain unchanged.

## Implementation
- Before atomic publication, RestoreCold now calls VerifyComplete on the *staged* directory with the authenticated manifest and key.
- This rejects missing, additional or modified staged files and repeats descriptor-relative regular-file, checksum, file-identity and mutation checks.
- Added a multi-file nested restore regression that verifies the published target against the signed inventory, and a corrupted-source regression requiring no target publication.

## Qualification boundaries
- Source verification, staged verification and publication are separate operations, not a single atomic snapshot. An attacker with write access to the private staging directory could still race the final check and rename.
- Staging creation, deletion and ancestor replacement require further hostile-concurrency qualification. In particular, cleanup currently uses pathname-based RemoveAll and must not be treated as hardened against privileged adversaries.
- Restore is intentionally opt-in and does not replace /opt/spamgate/data, restart systemd, change Postfix/Dovecot, or install a new mail configuration.
- Production host, ownership/ACL/xattr restoration, real data snapshot consistency, native update rollback and end-to-end acceptance remain unverified.

## Evidence
Prior exact HEAD 29a7b996c2a694db85f25169b4ecb31e1fa4ee77: engineering CI 44462116545 and isolated mail lab 44462116513 completed successfully. Those runs predate this change and do not qualify it.
During this pass, new CI runs for intermediate commits were queued or running. Final-HEAD CI and new regression execution must be checked separately; do not infer success from a commit.
