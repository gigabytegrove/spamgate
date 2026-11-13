# Persisted tenant-policy validation gate — 2026-11-13

## Change
The read-only policy preview endpoint now validates effective persisted recipient policies using the same limits as candidate policies before examining saved history. A corrupt or contradictory stored policy set produces HTTP 503 with a generic operator-facing error instead of an apparently credible replay. Explicit candidate policy sets retain the existing HTTP 400 validation path. This does not change live Milter policy selection, stored settings, or mail-server configuration.

## Regression
`TestValidateEffectivePreviewPolicies` covers empty/valid sets, case-insensitive duplicates, invalid mailbox, nonascending thresholds, out-of-range reject threshold, and more than 200 entries.

## Qualification boundaries
Source committed on main; Go tests and exact-HEAD CI must be independently checked. No production Postfix/Dovecot host was accessed, and this does not close any production gate. Remaining gates include real queue holds/releases, durable delivery, SMTP authentication, classifier false-positive calibration, browser acceptance, backup/restore, and native upgrade/rollback. Locked native paths and ports remain unchanged.
