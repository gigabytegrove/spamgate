# SpamGate

**Explainable mail filtering, policy management and quarantine — written in Go.**

SpamGate is a new Gigabyte Grove mail-security platform designed to replace the operational role of Rspamd over time, not a finished drop-in Rspamd clone. **Current development build: `0.2.0-alpha.2` (source).** It has a working scoring engine, browser control desk, persistent audit history and separate SMTP, Rspamd-HTTP and Milter integration modes. Milter and Rspamd-style HTTP now have tested protocol subsets; SPF, DKIM, exact-domain DMARC and optional ClamAV have initial implementations. **Full protocol parity, ARC, fuzzy matching and neural detection are not yet implemented. Bayesian training now has a restricted Web UI and persistent per-installation model, but advanced anti-poisoning and sample unlearning are outstanding.** Do **not** replace a production filter with this alpha without a controlled mail-flow and security evaluation.

## What works today

| Function | Current state |
| --- | --- |
| Go scanner: RFC 5322 parser, multipart MIME text, subject/header/content/URL and attachment heuristics | Implemented with documented limitations |
| Explainable weighted findings, exact symbol, detail, source and score | Implemented |
| Custom rules: email/domain/IP/recipient/header/subject/body/URL-domain, forced actions | Implemented |
| Admin-defined score thresholds: accept, tag, quarantine, reject | Implemented |
| Web-managed, persistent built-in signal weights and enable/disable overrides | Implemented |
| Configurable DNSBL zones and weights | Implemented; off by default |
| HTTP raw `.eml` scan API; scoped API keys | Implemented |
| Trusted SMTP content filter → outbound SMTP relay | Implemented; intentionally limited ESMTP, private network use only |
| Quarantine original SMTP messages, manual release/discard and retention purge | Implemented |
| Event journal, history search, statistics, per-message investigation, exports | Implemented |
| First-run wizard with claim key, sessions, user accounts, CSRF and access restrictions | Implemented |
| Personal sender allow/quarantine overrides for single-recipient mail | Implemented |
| Persistent settings, retention limits and periodic log compaction | Implemented |
| Milter v2–v6 wire listener (Postfix/Sendmail family) | Implemented tested subset; not certified against live MTAs |
| Rspamd HTTP `/checkv2`, `/check`, `/symbols`, `/scanv2` | Implemented subset; distinct port |
| SPF/DKIM/DMARC | Real DNS-backed SPF and DKIM verification; exact-domain DMARC subset |
| Antivirus | Optional ClamAV INSTREAM with fail-closed errors |
| Bayesian ham/spam training and bounded local classification | Implemented initial model and admin UI; no sample unlearning |
| ARC, fuzzy, neural, **full protocol parity** | **Not yet implemented** |
| Multi-node and enterprise directory integration | **Not yet implemented** |

## Quick install (Docker Compose)

Requirements: Docker Engine with the Compose plugin, a persistent data volume, and an HTTPS reverse proxy or a private management network.

```bash
git clone https://github.com/gigabytegrove/spamgate.git
cd spamgate
docker compose up -d --build
docker compose logs spamgate --tail=30
```

Open `http://<server>:38470` on a **trusted private network**. Find the `setup_key` in `docker compose logs spamgate`, paste it into the first-run wizard, choose the site name and create your administrator account. The key is single-use and changes if an unconfigured instance restarts. It is never returned by the unauthenticated API.

Before putting the console on the internet, deploy an HTTPS reverse proxy and set `SPAMGATE_SECURE_COOKIES=true` in `compose.yaml`. Protect access using network rules. The HTTP listener has no built-in TLS; do not send credentials over cleartext public networks.

**By default all MTA-facing filtering listeners are disabled:** the web console and HTTP API work without touching mail flow. To enable SMTP delivery, configure the five required SMTP variables described in [docs/OPERATIONS.md](docs/OPERATIONS.md), keep the filtering port within a trusted network, and route messages from your MTA into that port. SpamGate does not automatically modify any mail server.

## Quick install (native Go)

Use Go **1.27.3** or newer to build for current security patches (the module intentionally targets older Go language syntax and also compiles with Go 1.23). Confirm target operating system architecture support before deploying.

```bash
go test ./...
go vet ./...
go build -trimpath -o spamgate ./cmd/spamgate
mkdir -p ./data
./spamgate -data ./data -listen 0.0.0.0:38470
```

A single binary embeds the entire browser UI. No external database, Node.js runtime or frontend build step is required. The daemon writes `config.json`, `events.jsonl`, and `quarantine/` beneath the data directory. Take consistent backups of that directory and protect it as sensitive information.

## Scan an email using the API

In **API access**, create a key with `scan` permission. Send a real RFC 5322 `.eml` file:

```bash
curl --fail-with-body --request POST https://spamgate.example.com/api/v1/scan \
  --header "Authorization: Bearer $SPAMGATE_SCAN_TOKEN" \
  --header "Content-Type: message/rfc822" \
  --header "X-SpamGate-Sender: sender@example.net" \
  --header "X-SpamGate-Recipients: inbox@example.com" \
  --header "X-SpamGate-Client-IP: 203.0.113.9" \
  --data-binary @message.eml
```

`/api/v1/scan` provides an advisory decision and persists its evidence; **it does not execute any delivery or quarantine operation** for HTTP callers. Only the SMTP connector enforces delivery/rejection and retains quarantined message originals. Custom connectors must enforce decisions and fail safely on scan errors.

## Source and documentation

- [Operations, environment configuration and backup](docs/OPERATIONS.md)
- [HTTP API and JSON schemas](docs/API.md)
- [Server/protocol compatibility](docs/COMPATIBILITY.md)
- [Ports, Milter/HTTP wire contracts, antivirus configuration](docs/PROTOCOLS.md)
- [Detection engines and precise supported scope](docs/DETECTION_ENGINES.md)
- [Architecture and data handling](docs/ARCHITECTURE.md)
- [Security model and production precautions](docs/SECURITY.md)
- [Exhaustive feature plan and acceptance criteria](docs/ROADMAP.md)

The interface's visual direction is **postal dispatch ledger / contemporary operations typography**: warm limestone background, deep pine interface ink, vermilion alert accents, compact ledger tables, a message-decision inspector, and responsive administrative navigation. No external images or fonts are required.

## License

Copyright © 2026 Gigabyte Grove. **All rights reserved until a software license is explicitly selected and added.** An empty repository was provided without licensing instructions; no open-source grant is implied. A license decision is tracked in the roadmap.
