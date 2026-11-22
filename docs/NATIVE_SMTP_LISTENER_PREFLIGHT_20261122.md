# Native SMTP listener preflight — 2026-11-22

Scope: production gates #1, #2 and #6 (native SMTP startup safety and diagnostics). This is not delivery or mail-host qualification.

Before binding the SMTP content-filter socket, the listener now rejects a missing persistent store, uninitialized or mismatched scanner/store, absent fsync-backed delivery queue, missing relay, invalid relay configuration, invalid bind syntax, empty/nil trust CIDRs, and empty/invalid/duplicate recipient-domain allowlists. A failure returns a specific startup error instead of accepting connections that could panic or acknowledge mail without a durable path.

Architecture remains the native foreground launcher at /opt/spamgate/spamgate, spamgate-worker, /opt/spamgate/data, and Postfix Milter ports 38470/38472. No live mail host or systemd service was touched. This patch does not modify Milter handling.

Qualification: owner-controlled builder NOT EXECUTED; Go compilation NOT EXECUTED; regression tests NOT EXECUTED; production Postfix/Dovecot NOT EXECUTED. Source changes and tests are committed, but their execution and compatibility with the entire repository are unverified. No GitHub Actions were used.

Still open: actual durable queue crash/failure injection, Postfix hold/release and Dovecot Junk/INBOX disposition, SMTP AUTH interoperability, classifier precision/recall and false positives, tenant conflict policies, persistent diagnostics and alerting, browser workflows, cold backup/restore, native update/rollback, and independently recorded real-host acceptance. No issue is closed.
