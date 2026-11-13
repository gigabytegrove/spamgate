# Policy replay: temporary versus permanent SMTP rejection

## Change
Policy preview now exposes `totals.would_soft_reject` independently of `totals.would_reject`. A preserved historical forced `soft_reject` is a temporary SMTP failure (4xx), not a permanent 5xx rejection. Previous preview responses silently omitted this outcome from verdict counters, making a batch of previewed messages appear to have fewer hypothetical dispositions than it actually did.

The existing JSON fields remain unchanged; `would_soft_reject` is additive. Only determinate results enter verdict counters. Forced decisions remain preserved, and previews do not modify Postfix, Dovecot, policy settings, or message history.

## Regression coverage
`TestPolicyPreviewTemporaryRejectionTotals` checks distinct temporary and permanent rejection counts, a normal accept, forced preservation, and JSON serialization. `TestPolicyPreviewInvalidEvidenceNeverContributesTotals` verifies that indeterminate evidence cannot increment verdict, forced, change, or recipient-policy counters.

## Qualification boundary
These counters describe hypothetical scanner actions, **not** actual SMTP response codes or queue dispositions. No production mail-host integration, retry/delivery evidence, classifier accuracy calibration, or native upgrade/rollback is established by this change. Native foreground launcher, worker, persistent data and Milter ports remain unchanged.
