# Policy replay evidence integrity — 2026-11-12

Scope: native browser/API policy preview, not SMTP delivery or classifier retraining.

## Implemented
- Treat non-finite persisted scores as indeterminate rather than emitting invalid JSON or assigning a synthetic verdict.
- Treat unrecognized historical or forced actions as indeterminate; do not count them as changed or as hypothetical accept/tag/quarantine/reject.
- Preserve valid forced actions, existing per-mailbox selection, and global multi-recipient fallback.
- Expose `indeterminate` on affected items and in aggregate totals. The sanitized score of zero is only a JSON serialization fallback and **must not** be interpreted as actual evidence.
- Add table-driven regression tests for NaN, positive/negative infinity, unrecognized historical/forced actions, and valid forced verdicts.

## Qualification limits
These tests do not prove mail delivery, Postfix holds, Dovecot LMTP placement, or classifier false-positive rates. Production history corruption and the browser's handling of indeterminate rows require host-backed acceptance. Do not automatically alter Postfix or Dovecot settings.

Locked runtime remains `/opt/spamgate/spamgate` foreground launcher, `spamgate-worker`, `/opt/spamgate/data`, Milter ports 38470 and 38472. No Docker substitution.
