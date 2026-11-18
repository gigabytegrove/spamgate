# Windows device-alias recovery evidence — 2026-11-17

## Scope
Native Linux backup/restore portability only. No mail-server configuration, service, Docker image, or running Postfix/Dovecot instance was changed.

## Implementation
Windows treats superscript ¹, ², and ³ as digits in COM/LPT device names. The shared portable path guard now rejects COM¹, COM², COM³, LPT¹, LPT², LPT³ and the existing ASCII device aliases, including extension-bearing and nested paths. Ordinary names such as COM0, COM10 and LPT10 remain permitted. The manifest and archive safety boundaries call this shared guard.

## Regression evidence
Added invalid names to TestPortableBackupPathEvidence, exercising both safeName and validateManifestSemantics. Source was read back after the final test correction. No complete Go test suite was executed in this run: the execution host has Go 1.23.2 and cannot clone GitHub due to DNS failure. GitHub's commit workflow lookup is limited to PR-triggered runs; an empty response is **not** evidence that push CI passed.

## Outstanding qualification
This is a narrow recovery-path safety improvement, not a successful cold restore. Issue #8 remains open, as do issues #1–#9. Native Linux systemd update/rollback, real-data recovery, Postfix/Dovecot disposition, delivery durability, SMTP/authentication, classifier calibration, tenant policies, diagnostics and browser acceptance require independent end-to-end evidence. Do not claim beta readiness from this change.
