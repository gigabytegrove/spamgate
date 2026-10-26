# Deploying and operating SpamGate

## Modes

**Advisory API** (default): HTTP **38470** serves the management UI and `POST /api/v1/scan`. No SMTP traffic is accepted. No external DNSBL lookups are performed until enabled and configured. No messages are delivered.

**SMTP filter**: an approved upstream MTA sends SMTP over a private network to port **38473**. SpamGate accepts a message for an allowed recipient domain, records a decision, then rejects, quarantines or relays to your configured outbound MTA. This mode currently supports HELO/EHLO, MAIL, RCPT, DATA, RSET, NOOP and QUIT and trusted-client `XFORWARD ADDR` (records the original sender IP), with 8BITMIME and SIZE advertisement. No inbound SMTP AUTH/STARTTLS, CHUNKING, SMTPUTF8 or LMTP support is implemented on the **SMTP** port; the Milter worker is a separate service on port 38472.

**Rspamd-style HTTP**: enable `SPAMGATE_RSPAMD_LISTEN=0.0.0.0:38471` for supported `/checkv2`, `/check`, `/symbols`, `/scanv2` scan calls. Configure `SPAMGATE_RSPAMD_TRUSTED_CIDRS` to restrict client hosts, optionally add `SPAMGATE_RSPAMD_TOKEN`; this is **not** the admin API and does not modify mail transport itself. The caller is responsible for enforcing each action. Full Rspamd protocol parity is not complete.

**Milter**: enable `SPAMGATE_MILTER_LISTEN=0.0.0.0:38472` and **mandatory** `SPAMGATE_MILTER_TRUSTED_CIDRS`. The TCP Milter worker handles a tested subset of v2–v6 commands and actions, but has not been tested against live Postfix or Sendmail. Its quarantine action is an *MTA-side* request; it does not store an original quarantine blob locally.

**Antivirus**: optional ClamAV INSTREAM scanner using `SPAMGATE_CLAMAV_ADDRESS`. An unavailable ClamAV service **blocks scans** when enabled; a clean health endpoint does not mean ClamAV is reachable.

**Learning**: administrator-only **Spam learning** in the Web UI accepts explicitly labeled RFC 5322 samples, saves `bayes.json`, and activates the classifier only when both ham and spam training thresholds have been met.

## Configuration

| Variable or CLI argument | Required | Description |
|---|---|---|
| `-data /var/lib/spamgate` | Yes | Writable persistent directory, mode 0700 preferred |
| `-listen 0.0.0.0:38470` | Yes | Web interface and HTTP API listener; put behind HTTPS proxy |
| `SPAMGATE_SECURE_COOKIES=true` | Recommended for HTTPS | Marks the session cookie Secure; use when TLS termination is active |
| `SPAMGATE_RSPAMD_LISTEN=0.0.0.0:38471` | No | Enable the dedicated Rspamd-compatible HTTP scanner; omit to disable |
| `SPAMGATE_RSPAMD_TRUSTED_CIDRS=192.0.2.10/32` | Recommended if Rspamd HTTP enabled | Allow only known MTA scanner hosts; defaults to loopback if not specified |
| `SPAMGATE_RSPAMD_TOKEN` | Optional | Require an additional shared bearer token for Rspamd HTTP requests; do not reuse an admin secret |
| `SPAMGATE_MILTER_LISTEN=0.0.0.0:38472` | No | Enable the TCP Milter worker; omit to disable |
| `SPAMGATE_MILTER_TRUSTED_CIDRS=192.0.2.10/32` | **If Milter enabled** | Mandatory trusted mail-server IP/CIDR allowlist |
| `SPAMGATE_CLAMAV_ADDRESS=tcp://clamd.internal:3310` | No | Enable clamd INSTREAM antivirus scanning; service must be reachable on a trusted network |
| `SPAMGATE_SMTP_LISTEN=0.0.0.0:38473` | No | Enables SMTP filter; omit to disable |
| `SPAMGATE_SMTP_TRUSTED_CIDRS=192.0.2.10/32` | If SMTP enabled | Exact IPs/subnets allowed to connect; DO NOT use 0.0.0.0/0 |
| `SPAMGATE_ALLOWED_RECIPIENT_DOMAINS=example.org,example.net` | If SMTP enabled | Exact recipient domains the connector can relay |
| `SPAMGATE_RELAY_ADDRESS=relay.example.org:587` | If SMTP enabled | External SMTP relay receiving accepted messages |
| `SPAMGATE_RELAY_TLS=required` | Optional | `required` (STARTTLS, default), `implicit` (SMTPS 465) or `none` (private non-authenticated only) |
| `SPAMGATE_RELAY_USERNAME` | Optional | Outbound SMTP authentication user |
| `SPAMGATE_RELAY_PASSWORD` | Optional | Outbound SMTP password; provide through a protected secret mechanism |

**Do not point the outbound relay back at SpamGate's filtering listener.** That would form a mail loop. Configure relay hostnames and ports carefully. If outbound SMTP AUTH is enabled, plaintext relay transport (`SPAMGATE_RELAY_TLS=none`) is blocked.

The listener authorizes *client IP ranges* and *recipient domains*, not mailbox passwords. It is intended for a trusted MTA, **not public port 25**. For public SMTP or end-user submission, use a mature MTA that handles TLS/AUTH, authentication and transport reliability before passing messages to SpamGate.

## Compose setup

The included Compose recipe builds with the current Go 1.27.3 toolchain. It publishes host port **38470** for initial private testing; optional mail-facing ports **38471**, **38472**, and **38473** are commented out by default. To publish through Dokploy or another reverse proxy, attach the service to the deployment network and restrict or remove the host port mapping. If enabling any MTA-facing listener, expose its unique port only to specifically trusted mail server clients. Validate host port availability before deploying and change both the listener address and Compose mapping if a port conflicts. A volume preserves configuration and history across container restarts.

## Initial setup and access

1. Start the process. The console is unconfigured and emits a cryptographically random `setup_key` in its startup log.
2. Visit the web UI, paste the key, enter a unique admin username and a password at least 12 bytes long.
3. After setup, copy/paste the session into no other client; the cookie is HttpOnly, SameSite Strict, and expires after 12 hours.
4. Admins can add restricted mailbox accounts with explicit mailbox addresses in **Mailboxes**. They can only view recipient-matching history and create sender-specific allow/hold rules.
5. Use **API access** to issue a scan-only key for each mail server or custom connector. The token value is visible once and its SHA-256 hash is persisted.

For reverse proxies, preserve the original `Host` header. Do not strip `X-CSRF-Token`. Set the HTTPS proxy to reject HTTP or redirect before any credentials are sent.

## Mail decision rules

Default thresholds: tag at score 5, quarantine at 10, reject at 20. Scores are sums of built-in signals, custom rules and optionally DNSBL findings. The **Decision Inspector** lists symbols, source IDs, evidence and weights. In **Built-in signals** admins can override each detector weight (−100 to +100) or disable the detector; updates apply only to subsequent scans and are persisted in the configuration. A custom rule can force an action regardless of numeric thresholds. With multiple matching forced rules, the last matching rule in configured order wins.

- **accept**: SMTP connector passes the original message to its relay.
- **tag**: SMTP connector prepends `X-SpamGate-Result`, `X-SpamGate-Score` and `X-SpamGate-ID` before relay.
- **quarantine**: connector stores the original RFC 5322 bytes under the data directory and acknowledges receipt without relaying; admin can release later.
- **reject**: connector returns SMTP 550 after receiving DATA and persists metadata, but not the raw body.

Reclassification of a history event is an *audit operation*. It does not change the already executed mail transport result. To physically deliver previously quarantined mail, use the separate **Release** action. Release is deliberately disabled without a configured SMTP relay.

## Retention, performance and failure handling

History defaults to 30 days and 10,000 messages in an append-only JSONL journal with periodic compaction (daily, and after in-memory history eviction). Updates append replacement records using stable message IDs; the latest record wins on restart. Each successful journal append is fsynced. This simple format is convenient for backups and troubleshooting but is **not** a production multi-writer transactional database and is not intended for high-volume clustered deployments.

A history record stores sender, recipients, subject, score, rules, findings and operational metadata. For accepted/rejected messages the full body is *not* saved. SMTP quarantine saves raw originals (`0700` folder, `0600` files). The store deletes quarantine blobs when records expire or are evicted by configured retention, and administrators can permanently discard held originals in History. Offline filesystem cleanup and audit of deletion failures remain operator responsibilities; the deletion is not guaranteed to be atomic across storage and the journal.

SMTP rejects when an audit write fails; no success is acknowledged before the initial audit is durable. On an upstream delivery error it replies with a 451 temporary failure. If a message has been accepted by an upstream SMTP relay but local bookkeeping fails afterward, a warning is logged and the client still receives a success response to reduce duplicate delivery risk. **Crash-safe multi-stage queue recovery is not yet present.**

## Backup and restore

Stop SpamGate first for a consistent cold backup. Back up the entire data directory including `config.json`, `events.jsonl`, `bayes.json` (when trained), and `quarantine/`, retaining file permissions. Restore to a writable directory with the original private permissions, then restart. Never publish archive contents, tokens, quarantine mail or administrator password hashes.

## Checks

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/spamgate
curl --fail http://localhost:38470/healthz
```

The health endpoint is *liveness only*, not a downstream SMTP delivery guarantee. Monitor process logs and end-to-end test mail flow before routing real customer messages.
