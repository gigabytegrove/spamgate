# Native spool audit: explicit omitted-finding evidence

Date: 2026-11-05. Production gates #2 and #6 remain open.

## Problem

The forensic queue audit retained at most 512 findings and returned an incomplete-audit error after the limit, but the report did not state how many further findings had been suppressed. `len(Findings)` was not the total anomaly count, and the operator-facing `Explain` summary gave no count of omitted evidence.

## Change

`Report.DroppedFindings` now increments for every finding omitted after the 512-entry cap. JSON reports expose `dropped_findings`; `Explain` includes the count. The existing `Truncated` flag and fail-closed incomplete-audit error remain in place. The auditor remains read-only and bounded by 4,096 directory entries.

## Regression

The finding-limit regression requires exactly three omitted findings for 515 invalid filenames. The 512-finding boundary requires zero omitted findings. A separate test checks two omitted findings and the human-readable summary. Tests are committed but must be executed in exact-HEAD CI before any passing claim.

## Limits

This is diagnostic evidence accounting, not durable delivery or a transactional queue snapshot. The queue may mutate during scanning. Real Postfix/Dovecot end-to-end qualification, host fault injection, classifier measurement, UI acceptance, backup/restore, and native update/rollback remain outstanding. No production mail host or service configuration is changed.
