# Absolute spool-history ceilings — 2026-11-22

The native read-only `spamgate-spool-history` command now supports `-max-queued-count`, `-max-delivering-count`, and `-max-pending-count` (each defaults to -1, disabled). These check every observation, including the first. Existing per-interval growth limits and absolute dead-letter ceiling remain independent. A violation yields exit code 1 with a sample-indexed JSON reason; invalid negative limits below -1 yield exit code 2.

## Regression evidence and boundaries

Unit tests cover baseline and intermediate violations, inclusive thresholds, preserved prior failures, invalid limits, and incomplete evidence. CLI tests exercise a baseline violation and invalid configuration. The tests were committed but execution is not claimed until exact-HEAD CI completes. The diagnostics neither move nor delete mail and do not prove final Postfix/Dovecot disposition.

Architecture unchanged: permanent foreground launcher `/opt/spamgate/spamgate`, `spamgate-worker`, persistent `/opt/spamgate/data`, Milter ports 38470/38472. No Docker substitution or live mail-host modification.

All nine production issues remain open. The October 31 beta target has passed. Mail-host failure injection, authentication interoperability, classifier false-positive measurement, tenant isolation, browser acceptance, backup/restore and native update/rollback require separate qualification.
