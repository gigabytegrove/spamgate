# Native spool audit: bounded findings are not a successful audit

Date: 2026-11-04. Production gates #2 and #6 remain open.

## Defect
The read-only native spool auditor capped `Report.Findings` at 512 and set
`Report.Truncated` when later anomalies were discarded, but returned nil
error after completing directory traversal. A caller checking only the error
could interpret the incomplete forensic report as a successful queue audit.

## Correction
`Audit` now returns an explicit incomplete-audit error when the findings
limit is exceeded. It retains the bounded findings, counters, and truncation
flag for operator diagnosis. The directory identity check still precedes the
error, and no mail is replayed, deleted, or modified.

## Regression
`TestAuditFindingLimitFailsClosedWithoutQueueMutation` creates 515 invalid
published filenames, requires an error and 512 retained findings, verifies
counters and confirms every queue entry remains intact.
`TestAuditFindingLimitBoundaryStillReturnsCompleteReport` verifies that
exactly 512 findings do not falsely trigger an incomplete-audit error.

## Qualification limits
These tests are source-level regressions until executed by CI. Live spool
scans are not atomic. No real Postfix/Dovecot production-host test, durable
delivery qualification, or native update/rollback is claimed. The native
foreground launcher, worker, persistent data directory and Milter ports
remain unchanged.
