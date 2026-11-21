# Native delivery age qualification — 2026-11-21

The read-only `spamgate-spool-audit` now reports `oldest_queued_seconds` and `oldest_delivering_seconds` in JSON. Values are the maximum elapsed whole seconds since the original creation time among **verified, published, signed, lifecycle-valid** records in each state. Future timestamps are clamped to zero; lifecycle anomalies remain independent integrity findings. The timestamp is captured once at the start of the audit; live scans are not atomic snapshots.

Use `-max-queued-age-seconds=N` and `-max-delivering-age-seconds=N` for nonnegative operational limits. Defaults are -1 (disabled), and exact threshold equality passes. Threshold violations produce exit code 1 and `gate_failures`; invalid flags produce exit code 2. Age is **not** time since last retry, so repeated attempts cannot conceal a long-lived original. Age zero is also reported for empty queues.

These gates are diagnostics only: they do not retry, release, delete or mutate mail, do not establish final Dovecot delivery, and do not replace crash/failure-injection acceptance. A live mail-host trial, representative sustained load, exact-HEAD CI and independent delivery evidence are still required before beta qualification.
