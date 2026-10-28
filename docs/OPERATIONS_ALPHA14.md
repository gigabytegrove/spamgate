# SpamGate alpha.14 — persistent operations monitoring and threshold preview

These are functional additions to the independent native `spamgate-run` deployment, not new services. The runner and the established alpha.13 update mechanism are preserved unchanged.

## Persistent operations monitor

Authenticated administrator endpoints:

- `GET /api/v1/operations/monitor` — returns the bounded persistent history, open/resolved alert records, and evidence limitations; never queries an external mail provider.
- `POST /api/v1/operations/monitor/sample` — explicitly captures a new measured sample with CSRF protection (session) or an authorized administrative bearer token.
- `POST /api/v1/operations/monitor/alerts/{id}/ack` — records a durable actor, UTC timestamp, and 12–512-character reason. Repeated acknowledgement is rejected; acknowledgement does not clear an alert.

Five-minute background sampling runs within the SpamGate worker as long as its HTTP process is running. It stores only actual in-process scanner totals/errors, Milter connector count, scan elapsed time, and **SpamGate's own** SMTP delivery-queue sizes. The file is `<data-dir>/operations/monitor.json`, private `0600`, written via synced temporary file and atomic rename. The newest 2,016 snapshots and 256 alert records are retained (capped). On corrupt, oversized, or unreadable existing history, the monitor refuses writes and the UI shows a 503; it never automatically destroys or resets evidence.

Alerts open and resolve based on measured conditions: unreadable enabled SpamGate SMTP outbox (critical), any dead jobs (critical), queued backlog (warning, default 100), or scan errors newly observed across *same-process* samples (warning, default five). Optional integer thresholds (valid 1–100000): `SPAMGATE_MONITOR_BACKLOG_THRESHOLD` and `SPAMGATE_MONITOR_SCAN_ERROR_THRESHOLD`. Invalid values use safe documented defaults. Scan counts reset on worker restart and are tagged by randomly generated boot ID; no cross-restart subtraction is performed. Alerts are historical observations, not final Postfix status. Disabled SMTP outbox is normal for Postfix Milter mode, not an outage.

The Diagnostics page presents last sample timestamp and freshness, active alerts, acknowledgement, and a bounded table of recent measurements. It distinguishes actual observations from connector configuration. The monitoring file contains no message bodies, senders, recipients, subjects, IPs, SMTP queue IDs, or credentials.

## Threshold-only policy preview

`POST /api/v1/policy/preview` is admin-only, CSRF-protected, accepts candidate ascending finite global thresholds (0–1000), optional mailbox policies with the exact existing validation rules, and limit 1–500. It examines the newest retained scan scores and reports historical vs hypothetical scanner action, counts, forced-rule preservation, and global fallback for multi-recipient SMTP transactions. It does **not** mutate settings, original scan evidence, the queue, or recipient mailboxes; no external scanning occurs. It never asserts actual Postfix disposition or predictions from recomputed authentication, learning, or custom rule matches. The Protection policy page allows previewing the unsaved threshold form values.

## Qualification

Local Go package/full tests, race tests, static vet and negative API tests cover persistence/restart, corrupt evidence protection, retention, alert acknowledgement, permission boundaries, exact threshold boundaries, forced verdicts, safe recipient fallback, and non-mutating previews. Browser UI is covered by JavaScript rendering regressions; real Chrome/Firefox/Edge and live Postfix/Dovecot integration are separate gates. A source push or successful build is not proof of production mail safety.
