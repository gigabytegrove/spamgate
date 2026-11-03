# Native spool reconciliation accounting — 2026-11-03

## Scope

Read-only `internal/spoolaudit` accounting only. The permanent native launcher, worker, persistent data root and Milter listeners are unchanged. No live mail host or running Postfix configuration was modified.

## Defects and corrections

* Multiple identical `.pending-*` records referencing one valid published original could increment `pending_with_final` multiple times. The auditor now counts one verified pending-to-final identity per queue ID and reports `pending_final_duplicate` for additional matching pending records. Existing duplicate-pending findings remain visible.
* Published records without both integrity digests were included in `states` totals despite being marked legacy unsigned. Trusted state totals now require both validated digests and matching published filename/record ID. Such records remain counted in `published`, `legacy_unsigned` and findings.

## Verification boundary

Regression tests added: `TestDuplicatePendingFinalCountsOnlyOnce`, `TestUnsignedPublishedRecordDoesNotInflateTrustedStates`. Run `go test ./internal/spoolaudit ./cmd/spamgate-spool-audit` and full CI on the exact final commit. These tests are not a substitute for crash/disk-full injection, actual SMTP acknowledgements, Postfix HOLD/release, Dovecot delivery, native update/rollback, or production ISPConfig qualification. SHA-256 integrity fields are not cryptographic proof of record origin. Do not declare long-term beta readiness from these checks.
