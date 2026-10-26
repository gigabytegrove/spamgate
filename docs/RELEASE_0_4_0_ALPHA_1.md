# SpamGate 0.4.0-alpha.1 — operational workstream and acceptance limits

This release addresses material gaps without claiming complete Rspamd interoperability. All core changes have tests; no environment-specific Postfix/Exchange certification exists. Multi-node and enterprise directory integration stay deferred.

## Implemented in this release

- Durable, bounded, single-node SMTP outbox (500 entries / 512 MiB), restricted to configured relay integrations
- SMTP `250` occurs only after an on-disk spool write succeeds; spool full/failure yields `451`
- Startup recovery of queued SMTP originals, including when inbound SMTP listener is disabled
- Serialized delivery worker, exponential retry, 16-attempt dead-letter state, explicit manual retry/discard
- Admin-authenticated delivery queue API, Web UI workspace, and delivery/failed counters
- Explicit destructive-discard confirmation, actor logging, and best-effort message-history audit
- Weighted custom rule priority, rule expiration, edit, enable/disable and existing delete/create controls
- Server-side retained history search, verdict/recipient/sender/time filters and pagination, with mailbox isolation
- Administrator dry-run scanner (no recorded verdict) and text-only bounded quarantine-original preview
- Authenticated Prometheus-style retained counters (not rates/percentiles)
- Relay TCP reachability diagnostic (not full SMTP/TLS/auth handshake)
- Postfix controlled-integration / test / rollback documentation and SMTP durable-outbox integration test

## Not completed by this release

- Universal mail-server compatibility, all Milter actions and full Rspamd HTTP wire parity
- Full RFC conformance for SPF/DKIM/DMARC, cryptographic ARC validation/sealing
- Advanced phishing/URL reputation, deep recursive archive inspection, greylisting, rate limiting
- Per-mailbox policies for aliases/shared mailboxes, complete threat feed lifecycle
- Multi-tier roles, mailbox digest schedules, release requests, rich retention/legal hold
- Delivery status notifications (DSN), exactly-once SMTP transactions, redundant mail spools
- Production Windows code signing, on-Windows AV validation, end-to-end MTA certification
- Real-world Bayes/neural/fuzzy accuracy, false-positive evaluation and anti-poisoning tests

A **production-ready replacement** requires these acceptance gates before migration. In particular, a permanently failed outbox job currently requires an administrator to review it; SpamGate does not create a DSN/bounce or otherwise notify the envelope sender.
