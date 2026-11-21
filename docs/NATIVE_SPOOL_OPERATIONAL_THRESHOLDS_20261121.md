# Native delivery spool operational thresholds — 2026-11-21

The read-only `spamgate-spool-audit` command now supports `-max-queued`, `-max-dead`, and `-max-pending` (nonnegative integer; default -1 disables each threshold). A value of zero requires zero objects in the corresponding category. Limits are inclusive.

Example: `spamgate-spool-audit -dir /opt/spamgate/data/delivery-queue -json -max-queued=100 -max-dead=0 -max-pending=0`.

Exit codes: 0 complete clean audit and all enabled limits met; 1 integrity findings or threshold exceeded; 2 invalid arguments, failed audit or output failure. Threshold diagnostics are sent to stderr, preserving the existing privacy-limited JSON report on stdout. The queued and dead counts include only signed, verified published records without lifecycle anomalies; pending is the observed unpublished file count. A corrupt record cannot be used to certify a clean queue: it remains a finding.

These thresholds are operational tripwires, **not** a delivery SLA or proof of no lost mail. Live directory scans are not transactional snapshots. A concurrent writer can change the observed counts. Production qualification still requires real Postfix/Dovecot delivery and recovery, injected failures, measured queue retention, and host-specific permissions. No mail services or data are modified.
