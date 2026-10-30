# Detection event telemetry — October 30, 2026

Issue #6 gains authenticated Prometheus counters for messages containing
selected detection symbols. Fixed labels cover ZIP executable signatures,
expansion, traversal, risky members and symlinks, MIME inspection failures,
visible-link phishing, and ClamAV malware. Each symbol counts at most once
per scanned message, even if repeated in multiple attachments. Finding
details, sender addresses, recipients, domains, and subjects never become
metric labels. Snapshots are copied under a mutex; concurrent scans cannot
mutate the returned maps.

Counters are measured process-lifetime events, **not persisted** and not a
substitute for a retained metrics store. Authentication remains admin-only.
Tests exercise concurrent counting, deduplication, label allowlisting, snapshot
isolation, and endpoint authorization. Issue #6 remains open pending retained
history, actionable alerts and real injected-fault verification.
