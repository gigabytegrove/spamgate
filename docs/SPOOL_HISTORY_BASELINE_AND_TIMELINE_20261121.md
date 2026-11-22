# Spool history baseline and timeline qualification — 2026-11-21

## Operational defect corrected

The history evaluator applied `max-dead-count` only to the *after* sample of each interval. A dead-letter backlog already present in the first observation was omitted from that absolute ceiling check. A later reduction below the limit could allow the history to pass despite the initial violation.

The evaluator now checks the first baseline against the absolute dead-letter ceiling, while existing interval comparisons continue to check every subsequent observation. Growth thresholds still apply only to adjacent intervals. A baseline violation appears as `sample_0: dead_count=N exceeds max-dead-count=M` in `gate_failures`; the process returns 1 rather than 2.

The JSON result now includes a bounded `points` array, one entry per accepted report, containing only capture timestamp and aggregate queued, delivering, dead, and pending counts. No message content, sender, recipient, or queue identifier is exposed. The existing maximum of 1024 samples remains in force.

## Regression scope

`internal/spooltrend/series_baseline_test.go` checks a baseline above the dead-letter limit without subsequent growth, and a complete three-observation aggregate timeline. `cmd/spamgate-spool-history/main_test.go` checks JSON output and exit code for two reports whose dead counts exceed the absolute ceiling.

## Qualification limits

This is diagnostic integrity, not proof of SMTP acceptance, durable handoff, final Dovecot mailbox placement, tenant isolation, classifier accuracy, or a real production mail-host run. The original native launcher, worker, persistent data directory and Postfix Milter ports remain unchanged. No running mail service is modified. The October 31 beta target has passed; all nine production issues remain open until their independent acceptance evidence exists.
