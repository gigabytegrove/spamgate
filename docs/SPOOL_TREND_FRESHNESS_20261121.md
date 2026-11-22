# Spool trend evidence freshness qualification — 2026-11-21

The read-only native `spamgate-spool-trend` command accepts three optional freshness controls:

- `-require-timestamps`: reject legacy audit reports without `captured_at`.
- `-max-snapshot-age=15m`: reject a later report older than 15 minutes relative to the invocation clock.
- `-max-snapshot-gap=1h`: reject comparisons whose capture timestamps are separated by more than one hour.

All controls default to disabled to preserve legacy compatibility. Any nonzero age or gap limit implicitly requires both timestamps. Invalid negative durations, missing timestamps under enforcement, stale evidence, reversed chronology and excessive capture gaps return exit status 2 (invalid evidence). A qualified comparison exceeding growth thresholds returns exit status 1. Successful qualification returns 0.

Example: `spamgate-spool-trend -before /secure/before.json -after /secure/after.json -require-timestamps -max-snapshot-age=15m -max-snapshot-gap=1h -max-queue-growth=10`.

This is read-only operational evidence gating; timestamps are not authenticated and do not establish that reports came from the same host or represent coherent queue snapshots. File-system races, evidence provenance, real Postfix/Dovecot mailbox placement, crash durability, SMTP/authentication, classifier accuracy, tenant policy, browser acceptance, backup/restore and update rollback still require independent qualification. No running mail server or systemd service is modified.

Verification: source changes and tests committed; execution and exact-HEAD CI results must be inspected separately. Do not claim beta acceptance from this gate.
