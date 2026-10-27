# SpamGate

## Install directly on a Linux mail server — no ZIP or Docker

The native source-to-service installer downloads and verifies the official patched Go 1.27.3 toolchain (only if missing), tests and builds SpamGate, and installs its systemd service **without modifying your mail server configuration**:

```bash
git clone https://github.com/gigabytegrove/spamgate.git
cd spamgate
bash scripts/install-native-from-source.sh
```

Run as a regular user; it prompts for `sudo` only when installing the service. This repository is private, so `git clone` requires GitHub access. For a non-installing build use `bash scripts/install-native-from-source.sh --build-only`. The local Web UI is at `http://127.0.0.1:38470` after first-run setup. **Alpha: do not attach live MTA mail routing until qualified.**

Prebuilt native artifacts are planned for [GitHub Releases](https://github.com/gigabytegrove/spamgate/releases), but are unavailable until the [build workflow](https://github.com/gigabytegrove/spamgate/actions/workflows/native-prerelease.yml) passes. The previous chat ZIP links are not dependable distribution.


## v0.4.0-alpha.2 native-first mail-server deployment

- Install SpamGate directly on the existing Linux mail host as a native binary/systemd service, without Docker or SMTP reinjection.
- New native installations enable a loopback-only Postfix-compatible Milter (`127.0.0.1:38472`), without touching MTA or hosting-panel settings.
- Run `sudo spamgate -mailserver-report` or use the Mail integrations screen for read-only identification of the local Postfix/Exim and common hosting panels.
- On **unmanaged Postfix**, use `sudo /usr/local/libexec/spamgate/configure-postfix --preview` then an explicitly confirmed, backup/validation/rollback-protected apply. On ISPConfig, cPanel, Plesk and DirectAdmin, the helper refuses writes.
- **cPanel/Exim is not integrated yet.** Docker remains supported as an optional deployment. Read the [native integration guide](docs/NATIVE_MAIL_SERVERS.md) before directing live email at this alpha.

## v0.4.0-alpha.1 operational features

Durable single-node SMTP outbox with retry and dead-letter review, first-class **Delivery queue** administration screen, time-bounded rule editing and priority, search across retained history, dry-run scan API, safe quarantine preview, relay TCP reachability probe and admin-only `/api/v1/metrics` counters. On-disk spool records are private and preserve accepted email until delivery or explicit discard; the outbox is **at-least-once**, not exactly-once, and does not yet send failure DSNs. The queue only operates when an upstream relay is configured; SMTP is disabled on a clean installation.

**Important:** This is an alpha with no live Postfix/Sendmail/Exchange certification and no full Rspamd protocol parity. The project is still **not** a production replacement. Review [Postfix integration](docs/POSTFIX_SMTP_INTEGRATION.md) and [release capability/gaps](docs/RELEASE_0_4_0_ALPHA_1.md). All former unsigned Windows builds remain unreleased developer previews; do not bypass Defender.


> **Windows distribution hold (2026-10-26):** Earlier alpha Windows binaries were unsigned and compiled with an outdated Go toolchain. See [release security](docs/RELEASE_SECURITY.md) before distributing executables. No Windows package is currently certified as Defender-clean.

**Explainable mail filtering, policy management and quarantine — written in Go.**

**Primary deployment: native Linux binary on the existing mail server.** Docker is optional. For Postfix (including ISPConfig), the local Milter is the integration path. For cPanel/WHM the native Exim adapter is **not yet certified**. See [Native mail server installation](docs/NATIVE_MAIL_SERVERS.md).

SpamGate is a new Gigabyte Grove mail-security platform designed to replace the operational role of Rspamd over time, not a finished drop-in Rspamd clone. **Current development source: `0.3.0-alpha.4` (redesigned Web UI and Windows GUI-subsystem preview; signed native release still pending).** It has a working scoring engine, browser control desk, persistent audit history and separate SMTP, Rspamd-HTTP, Milter and optional controller-style HTTP integration modes. Milter and Rspamd HTTP remain tested subsets; SPF, DKIM, exact-domain DMARC, Bayes, fuzzy similarity, a manually trained local neural network and optional ClamAV have limited implementations. **Full Rspamd parity, cryptographic ARC validation/sealing and production-ready model evaluation are not yet implemented.** Do **not** replace a production filter with this alpha without a controlled mail-flow and security evaluation.

## What works today

| Function | Current state |
| --- | --- |
| Go scanner: RFC 5322 parser, multipart MIME text, subject/header/content/URL and attachment heuristics | Implemented with documented limitations |
| Explainable weighted findings, exact symbol, detail, source and score | Implemented |
| Custom rules: email/domain/IP/recipient/header/subject/body/URL-domain, forced actions | Implemented |
| Admin-defined score thresholds: accept, tag, quarantine, reject | Implemented
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
| ARC chain structure diagnostics | Implemented; **not cryptographic ARC authentication** |
| Bayesian learning | Admin-supervised corpus and scoring with persistent state |
| Fuzzy near-duplicate reputation | Persistent supervised SimHash fingerprints, 90-day expiry, deletion and admin UI |
| Neural post-classification | CPU-only 12-unit hidden-layer model trained on confirmed historical symbol findings; alpha, no automatic labels |
| Controller-style HTTP `/learnspam`, `/learnham`, `/stat`, `/symbols`, `/actions` | Optional, credentialed subset on its own port 38474 |
| **Full Rspamd protocol parity, cryptographic ARC verification/sealing** | **Not yet implemented** |
| Multi-node and enterprise directory integration | **Not yet implemented** |

## Direct Windows preview (no shell)

On Windows, double-click the **GUI-subsystem `spamgate.exe`** from a trusted build. A command window and PowerShell launcher are not required. SpamGate opens the browser-hosted console, displays the one-time claim key in a native Windows dialog, and stores local data in `%LOCALAPPDATA%\SpamGate`. Navigable management pages have permanent URLs such as `/overview`, `/messages`, `/rules`, `/signals`, `/policy` and `/connections`. See [portable Windows](docs/PORTABLE_WINDOWS.md).

**This is still unsigned alpha software and has not been cleared by Windows Defender.** Do not disable Windows protections to run it. Signed distribution is tracked separately in [release security](docs/RELEASE_SECURITY.md).

## Install: native binary (recommended)

SpamGate runs as a **real operating-system service**, without Docker, a separate database, Node.js or Go on the machine being protected. Download the matching OS/CPU **verified binary archive** (`linux-amd64`, `linux-arm64`, `windows-amd64` or `windows-arm64`) from a validated release; do not try to run a source ZIP as an installer. **Do not use the previous unsigned Windows alpha packages as production releases.** Extract the verified archive and use its included script.

**Linux (systemd)**:

```bash
sudo ./install-linux.sh
sudo /usr/local/bin/spamgate -mailserver-report
sudo systemctl status spamgate --no-pager
sudo journalctl -u spamgate --no-pager -n 40
```

**Windows (elevated PowerShell 5.1+)**:

```powershell
.\install-windows.ps1
Get-Service SpamGate
Get-Content "$env:ProgramData\SpamGate\spamgate.log" -Tail 40
```

Visit <http://127.0.0.1:38470> **from the same computer** and use the one-time setup key shown in the logs to configure an administrator. The native Linux installer starts a **loopback-only local Milter** on a new installation, but does not touch any MTA configuration. The service is installed to start at boot and uses a dedicated unprivileged identity (`spamgate` on Linux, `LocalService` on Windows). All settings and mail history persist across upgrades and remain available after uninstalling. To expose the console beyond localhost, deliberately set a trusted interface and protect access with an HTTPS reverse proxy; do not put HTTP administrator login on the public Internet.

See [full Windows and Linux install/upgrade/uninstall instructions](docs/INSTALLATION.md). **Only unsigned development archives** are created with `bash scripts/build-release.sh`; public Windows releases require the signing and verification steps in [release security](docs/RELEASE_SECURITY.md).

## Optional deployment: Docker Compose

```bash
git clone https://github.com/gigabytegrove/spamgate.git
cd spamgate
docker compose up -d --build
docker compose logs spamgate --tail=40
```

Docker binds the management API/Web UI on container port `38470`. The example Compose file publishes it on the Docker host, so **restrict it using the host firewall/reverse proxy**. MTA-facing ports are disabled by default. A controller secret is only needed if the optional controller is enabled. See [deployment documentation](docs/INSTALLATION.md) and [operations](docs/OPERATIONS.md).

## Developer source build

Go 1.27.3 (recommended for current security fixes) or another Go toolchain compatible with the `go.mod` language version is required **only to build from source**:

```bash
go test ./...
go vet ./...
go build -trimpath -o spamgate ./cmd/spamgate
./spamgate -data ./data -listen 127.0.0.1:38470
```

The web UI is embedded. The data directory holds `config.json`, `events.jsonl`, the training models and `quarantine/`. Protect that data as confidential email information and perform consistent backups with SpamGate stopped.

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

- [Native Windows/Linux installation, upgrades and uninstall](docs/INSTALLATION.md)
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


## Threat operations interface (alpha.4)

The Web UI has addressable operational screens: `/overview` (command center), `/investigations` (flagged evidence and manual reclassification), `/quarantine` (originals actually held by the SMTP filter), `/messages` (complete visible mail log), `/threat-intelligence` (reputation and signal frequency), and `/scan-workbench` (advisory .eml tests). Administration retains policy rules, DNS lists, signal weights, classifier training, access controls, and integration instructions. The command center uses real retained data, never fabricated demo statistics; its counts are **not** lifetime delivery metrics.

Administrators see `/api/v1/runtime`, a configuration inventory that describes which listener processes were enabled at application startup. **Configured does not mean operational or connected to a real mail server.** Runtime details are never available to unauthenticated clients or mailbox-only accounts.

The previous source-only and unsigned Windows development builds remain unsuitable for production use; see [release security](docs/RELEASE_SECURITY.md).
