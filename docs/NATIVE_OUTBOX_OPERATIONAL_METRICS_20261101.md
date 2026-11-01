# Native outbox operational metrics — 2026-11-01

Production gates: #2 (durable recovery), #6 (actionable diagnostics), #7 (operations UI).

## Defect

The authenticated Prometheus metrics endpoint exposed only queued, delivering and dead records. A crash-recovered delivered record waiting for history finalization, or an administrator's discard_pending original, was missing from per-state metrics. Fully synced unpublished .pending-* evidence and its reserved bytes were also invisible. Consequently, operators could mistake an unsafe or nonempty outbox for a clean one.

## Change

The native queue snapshot now counts delivered records explicitly. The authenticated /api/v1/metrics endpoint emits a coherent set of gauges from a single validated snapshot:

- spamgate_outbox_jobs: total published records
- spamgate_outbox_messages{status="queued|delivering|dead|delivered|discard_pending"}: exhaustive state counts
- spamgate_outbox_bytes: original bytes in published records
- spamgate_outbox_unpublished_records and spamgate_outbox_unpublished_bytes: forensic temporary-file inventory
- spamgate_outbox_oldest_active_age_seconds: age of oldest queued/delivering original, zero when none
- spamgate_outbox_due_jobs: queued/delivering records with a due retry or recovery attempt

No message IDs, sender/recipient addresses, subjects, raw message content or SMTP error strings are exported. Disabled and corrupt queues retain the existing availability/error gauges; corrupt inventory does **not** emit misleading zero job counts. The age and due gauges are instantaneous observations, not historical metrics, and do not prove delivery.

## Verification scope

Added native queue state accounting and authenticated HTTP tests with a real durable spool, injected history-journal failure, preserved discard_pending original and unpublished evidence. The existing corrupt-inventory HTTP regression remains required. CI and production-host verification must be reported separately; this does not complete issue #6's retained time-series, alerting or live-host fault-injection acceptance criteria.

Architecture remains unchanged: native foreground launcher /opt/spamgate/spamgate, spamgate-worker, /opt/spamgate/data and Milter ports 38470/38472. No Docker substitution, auto-upgrade or mail-server configuration mutation.
