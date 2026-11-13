# Policy preview: contradictory forced-verdict evidence (2026-11-13)

Scope: GitHub issue #4, read-only historical policy preview.

A saved scoring trace can report a forced action that conflicts with the message's saved final action. Previously the preview unconditionally replayed the forced action, potentially counting an impossible historical-to-candidate transition. The preview now marks such a record indeterminate and excludes it from hypothetical disposition totals, change counts, and transition matrices. Matching forced verdicts are still preserved; missing forced actions continue through ordinary score replay.

The check occurs after the existing finite-score, action-enumeration and forced-action-enumeration guards, before recipient threshold selection. No SMTP action, policy persistence, mail delivery, or production host configuration is changed.

Regression: `TestPolicyPreviewConflictingForcedEvidenceIsIndeterminate` covers matching and contradictory accept/reject/tempfail/quarantine verdicts, and `TestPolicyPreviewConflictingForcedEvidenceDoesNotPolluteTotals` covers mixed records.

Qualification boundaries: these tests are source regressions only until an exact-commit Go test/CI run is observed. They do not establish whether the historical inconsistency is possible in live mail processing, nor do they qualify actual Postfix holds, Dovecot disposition, delivery durability, authentication, classifier precision, browser workflows, or native recovery. Issue #4 and the overall beta gate remain open.
