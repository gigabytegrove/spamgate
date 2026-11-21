# Native delivery-age distribution and dead-letter SLA

The read-only `spamgate-spool-audit -json` report now includes `queue_age_buckets` for verified, signed, published `queued`, `delivering`, and `dead` records. Buckets are mutually exclusive: under 300 seconds, 300–3599, 3600–86399, and 86400 or more. The original message creation time is used, not the last retry or state transition. `oldest_dead_seconds` exposes the longest-lived verified dead-letter item. `-max-dead-age-seconds=N` fails qualification when that age exceeds N; -1 disables it.

This is observation, not evidence of successful delivery. Unsigned, unreadable, lifecycle-invalid and pending records are excluded from age distributions and separately fail integrity qualification. Concurrent changes are not a transactional snapshot. No spool content is modified; no running Postfix/Dovecot service is reconfigured. Production-host failure injection, retained trends and mailbox delivery remain outstanding.
