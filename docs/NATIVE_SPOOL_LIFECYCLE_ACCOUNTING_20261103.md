# Native spool lifecycle evidence accounting — 2026-11-03

## Defect
The read-only auditor previously counted digest-valid records with impossible delivery lifecycles as trusted published states and could count a matching invalid pending/final pair as verified reconciliation.

## Fix
Published state totals now require a matching queue ID, both valid integrity digests, and zero lifecycle anomalies. Pending/final reconciliation also requires both records to have no lifecycle anomalies; otherwise `pending_final_lifecycle_invalid` is reported. No mail is replayed, deleted or rewritten.

## Regression
`TestInvalidSignedLifecycleExcludedFromTrustedEvidence` checks a signed delivered record with zero attempts, its exclusion from trusted totals and reconciliation, read-only preservation, and a valid completed-attempt positive control.

## Limits
Digests are not cryptographic origin signatures. Live scans are not atomic snapshots. This does not prove actual SMTP acceptance, crash recovery, Postfix HOLD/release, Dovecot delivery or production readiness. GitHub issues #1–#9 remain open until their full acceptance gates pass.
