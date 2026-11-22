# Sustained native spool-pressure qualification (2026-11-22)

The read-only `spamgate-spool-history` CLI now supports `-max-sustained-queued`, `-max-sustained-delivering`, `-max-sustained-pending` (all default -1, disabled), and `-min-sustained-samples` (default 2, valid 2–1024). A breach is reported only when the count is **strictly greater** than its threshold for at least the specified number of consecutive captures. A one-capture spike does not trigger a two-capture sustained alert. Each continuous run generates one sample-indexed failure. Existing growth, absolute ceiling, freshness and evidence gates remain active and independent.

Example: `spamgate-spool-history -report /opt/spamgate/data/audit-1.json -report /opt/spamgate/data/audit-2.json -report /opt/spamgate/data/audit-3.json -max-sustained-queued 100 -min-sustained-samples 3`.

The command emits JSON and exits 0 for a passing gate, 1 for operational breaches, and 2 for invalid input/evidence. No Postfix/Dovecot configuration, queue entry, mailbox, or running mail process is modified. This is **not** a proof of final delivery or production-host qualification. Capture frequency determines how much real time the consecutive-sample requirement represents; operators should also set `-max-snapshot-gap` to reject sparse observations. The history is bounded at 1024 samples.

Verification boundary: regression tests were added, but this change requires successful exact-HEAD CI and independent mail-host evidence before being counted toward beta acceptance. Issues #1–#9 remain open.
