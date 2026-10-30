# Relay negotiation and queue observability — beta gate

The authenticated relay probe now requires a valid SMTP 220 greeting and a successful **EHLO** reply. A server that only accepts HELO is not reported as ESMTP-ready. Required STARTTLS must be advertised, accepted, and verified against the system certificate trust store, followed by a second EHLO. AUTH is reported from the post-TLS extensions only. Implicit TLS is verified before reading the banner. No AUTH, MAIL, RCPT or DATA is sent.

A relay probe is not an authentication or delivery test. Plaintext relay mode with configured credentials is explicitly warned about; it is not silently reported as credential-safe.

The admin-only Prometheus endpoint now emits `spamgate_outbox_snapshot_available` and `spamgate_outbox_snapshot_error`. A corrupt/unreadable enabled queue reports 0/1 respectively instead of silently omitting outbox metrics. It does not publish stale queue counts or leak file paths. Disabled queue reports 0/0. Existing persistent operations-monitor alerts remain independent.

Regression fixtures cover HELO-only fallback, AUTH advertisement without sending credentials, STARTTLS handshake failure, and damaged queue metrics. Real Postfix/Dovecot delivery, trust-store deployment, live SMTP AUTH, and alert routing remain unqualified.
