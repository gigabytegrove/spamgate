# Deploying and operating SpamGate

## Modes

**Advisory API** (default): HTTP 8080 serves the management UI and `POST /api/v1/scan`. No SMTP traffic is accepted. No external DNSBL lookups are performed until enabled and configured. No messages are delivered.

**SMTP filter**: an approved upstream MTA sends SMTP over a private network to port 2525. SpamGate accepts a message for an allowed recipient domain, records a decision, then rejects, quarantines or relays to your configured outbound MTA. This mode currently supports HELO/EHLO, MAIL, RCPT, DATA, RSET, NOOP and QUIT, with 8BITMIME and SIZE advertisement. No inbound SMTP AUTH/STARTTLS, CHUNKING, SMTPUTF8, LMTP, XFORWARD or Milter support is implemented.

## Configuration

| Variable or CLI argument | Required | Description |
|---|---|---|
| `-data /var/lib/spamgate` | Yes | Writable persistent directory, mode 0700 preferred |
| `-listen 0.0.0.0:8080` | Yes | Web interface and HTTP API listener; put behind HTTPS proxy |
| `SPAMGATE_SECURE_COOKIES=true` | Recommended for HTTPS | Marks the session cookie Secure; use when TLS termination is active |
| `SPAMGATE_SMTP_LISTEN=0.0.0.0:2525` | No | Enables SMTP filter; omit to disable |
| `SPAMGATE_SMTP_TRUSTED_CIDRS=192.0.2.10/32` | If SMTP enabled | Exact IPs/subnets allowed to connect; DO NOT use 0.0.0.0/0 |
| `SPAMGATE_ALLOWED_RECIPIENT_DOMAINS=example.org,example.net` | If SMTP enabled | Exact recipient domains the connector can relay |
| `SPAMGATE_RELAY_ADDRESS=relay.example.org:587` | If SMTP enabled | External SMTP relay receiving accepted messages |
| `SPAMGATE_RELAY_TLS=required` | Optional | `required` (STARTTLS, default), `implicit` (SMTPS 465) or `none` (private non-authenticated only) |
| `SPAMGATE_RELAY_USERNAME` | Optional | Outbound SMTP authentication user |
| `SPAMGATE_RELAY_PASSWORD` | Optional | Outbound SMTP password; provide through a protected secret mechanism |

**Do not point the outbound relay back at SpamGate's filtering listener.** That would form a mail loop. Configure relay hostnames and ports carefully. If outbound SMTP AUTH is enabled, plaintext relay transport (`SPAMGATE_RELAY_TLS=none`) is blocked.

The listener authorizes *client IP ranges* and *recipient domains*, not mailbox passwords. It is intended for a trusted MTA, **not public port 25**. For public SMTP or end-user submission, use a mature MTA that handles TLS/AUTH, authentication and transport reliability before passing messages to SpamGate.

## Compose setup

The included Compose recipe builds with the current Go 1.27.3 toolchain. It opens host web port 8080 for initial private testing. To publish through Dokploy or another reverse proxy, attach the service to the deployment network and restrict or remove the host port mapping. If enabling SMTP, expose the filter port only to specifically trusted mail server clients. A volume preserves configuration and history across container restarts.

## Initial setup and access

1. Start the process. The console is unconfigured and emits a cryptographically random `setup_key` in its startup log.
2. Visit the web UI, paste the key, enter a unique admin username and a password at least 12 bytes long.
3. After setup, copy/paste the session into no other client; the cookie is HttpOnly, SameSite Strict, and expires after 12 hours.
4. Admins can add restricted mailbox accounts with explicit mailbox addresses in **Mailboxes**. They can only view recipient-matching history and create sender-specific allow/hold rules.
5. Use **API access** to issue a scan-only key for each mail server or custom connector. The token value is visible once and its SHA-256 hash is persisted.

For reverse proxies, preserve the original `Host` header. Do not strip `X-CSRF-Token`. Set the HTTPS proxy to reject HTTP or redirect before any credentials are sent.

## Mail decision rules

Default thresholds: tag at score 5, quarantine at 10, reject at 20. Scores are sums of built-in signals, custom rules and optionally DNSBL findings. The **Decision Inspector** lists symbols, source IDs, evidence and weights. A custom rule can force an action regardless of numeric thresholds. With multiple matching forced rules, the last matching rule in configured order wins.

- **accept**: SMTP connector passes the original message to its relay.
- **tag**: SMTP connector prepends `X-SpamGate-Result`, `X-SpamGate-Score` and `X-SpamGate-ID` before relay.
- **quarantine**: connector stores the original RFC 5322 bytes under the data directory and acknowledges receipt without relaying; admin can release later.
- **reject**: connector returns SMTP 550 after receiving DATA and persists metadata, but not the raw body.

Reclassification of a history event is an *audit operation*. It does not change the already executed mail transport result. To physically deliver previously quarantined mail, use the separate **Release** action. Release is deliberately disabled without a configured SMTP relay.

## Retention, performance and failure handling

History defaults to 30 days and 10,000 messages in an append-only JSONL journal with periodic compaction (daily, and after in-memory history eviction). Updates append replacement records using stable message IDs; the latest record wins on restart. Each successful journal append is fsynced. This simple format is convenient for backups and troubleshooting but is **not** a production multi-writer transactional database and is not intended for high-volume clustered deployments.

A history record stores sender, recipients, subject, score, rules, findings and operational metadata. For accepted/rejected messages the full body is *not* saved. SMTP quarantine saves raw originals (`0700` folder, `0600` files). Quarantine blobs are not yet automatically purged by history retention and require a separate privacy/expiry workflow in production.

SMTP rejects when an audit write fails; no success is acknowledged before the initial audit is durable. On an upstream delivery error it replies with a 451 temporary failure. If a message has been accepted by an upstream SMTP relay but local bookkeeping fails afterward, a warning is logged and the client still receives a success response to reduce duplicate delivery risk. **Crash-safe multi-stage queue recovery is not yet present.**

## Backup and restore

Stop SpamGate first for a consistent cold backup. Back up the entire data directory including `config.json`, `events.jsonl` and `quarantine/`, retaining file permissions. Restore to a writable directory with the original private permissions, then restart. Never publish archive contents, tokens, quarantine mail or administrator password hashes.

## Checks

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/spamgate
curl --fail http://localhost:8080/healthz
```

The health endpoint is *liveness only*, not a downstream SMTP delivery guarantee. Monitor process logs and end-to-end test mail flow before routing real customer messages.
