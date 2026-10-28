# Native-first deployment on an existing mail server

SpamGate's primary Linux installation is **a standalone Go executable supervised by systemd**, on the same server as the MTA. Neither Docker nor an SMTP forwarding gateway is required for Postfix Milter mode. Docker remains an independent option, not the normal deployment.

## Supported integration stages

| Host | Native binary and Web UI | Connection | Automatic mail-config changes | Qualification |
|---|---|---|---|---|
| Linux + plain Postfix | Yes | TCP Milter `127.0.0.1:38472` | Explicit opt-in via `configure-postfix.sh` | Milter subset tested in isolation; real Postfix compatibility **not yet certified** |
| ISPConfig + Postfix | Yes | TCP Milter | **Never automated**; ISPConfig regeneration/persistence must be verified by operator | Uncertified |
| cPanel + Exim | Yes | **Not yet provided as a turnkey Exim adapter** | **Never automated**; use WHM Exim Configuration Manager for future adapter | Not integrated |
| Plesk / DirectAdmin | Yes | Depends on local MTA | **Never automated** | Not integrated |
| Custom MTA / Windows / macOS | Host-specific binary where available | HTTP scan API, SMTP or Milter as appropriate | Manual | Not generally certified |
| Remote/filtering appliance | Yes | Private-network Milter/SMTP/HTTP | Manual | Optional |

Installing a daemon does not automatically protect mail. A mail server must be explicitly connected, and real transaction acceptance/rejection must be tested before production routing.

## Linux service install

1. Obtain a verified native Linux archive from a proper release. A source ZIP is not a binary package. For development, compile with a supported patched Go toolchain: `CGO_ENABLED=0 go build -trimpath -o spamgate ./cmd/spamgate`.
2. Copy `spamgate`, `install-linux.sh` and `configure-postfix.sh` into the same directory, then run `sudo ./install-linux.sh`. The installer also installs the helper permanently at `/usr/local/libexec/spamgate/configure-postfix`.
3. The installer runs the daemon as dedicated `spamgate` user, with `/var/lib/spamgate` for data, `/etc/spamgate/spamgate.env` for service settings and `/usr/local/bin/spamgate` for the binary. The Web UI binds `0.0.0.0:38470` (all IPv4 interfaces). Restrict administration access to the trusted LAN or an HTTPS proxy. On a **fresh** native install, local Milter binds `127.0.0.1:38472`, trusting only `127.0.0.1/32`. No MTA settings or firewall rules are changed. Use `--no-local-milter` to opt out; on an existing installation, use `--enable-local-milter` to append Milter settings without replacing existing environment settings.
4. Check `sudo systemctl status spamgate`, `sudo journalctl -u spamgate -n 60 --no-pager` and `sudo /usr/local/bin/spamgate -mailserver-report` for a read-only JSON host inventory.
5. Create the first admin using the one-time setup key and check the Web UI over a trusted LAN or authenticated HTTPS proxy. Never expose the plaintext management login to the public Internet.

`/api/v1/host` is an **admin-only, read-only** version of the local host report; the Web UI shows it under Mail integrations. Containerized deployments inspect the container filesystem, **not the host's**.

## Postfix (no hosting panel)

Use the native Milter before-queue path. It allows Postfix to remain responsible for SMTP acceptance and delivery; SpamGate does not need to create its own SMTP delivery route. The SpamGate listener is not a mailbox server.

1. Verify `spamgate -mailserver-report` detects Postfix and reports `milter_ready: true`. Finish SpamGate's first-run setup first.
2. Inspect other Postfix milters (`postconf -h smtpd_milters`), DKIM signing, antivirus and current rejection behavior. **Do not install two competing spam classifiers blindly.** Ensure you can access a recovery console.
3. Run `sudo /usr/local/libexec/spamgate/configure-postfix --preview`. This reads configuration and prints a proposed change without modifying anything.
4. On **unmanaged Postfix only**, after test mail has been scheduled, run `sudo /usr/local/libexec/spamgate/configure-postfix --apply --confirm POSTFIX-MILTER`. If other milters already exist, this refuses unless `--allow-existing-milters` is supplied after explicit review. The script retains existing Milter order, adds only SpamGate to `smtpd_milters`, backs up `main.cf` under `/var/backups/spamgate/postfix`, checks the configuration and reloads Postfix. No `non_smtpd_milters`, `milter_default_action`, or MTA listener ports are changed.
5. Verify `postfix check`, `postconf -h smtpd_milters`, live test mail (safe, spam-tagged, rejected and temporary-failure paths), and the SpamGate message inspector. Roll back without deleting third-party milters using `sudo /usr/local/libexec/spamgate/configure-postfix --detach --confirm POSTFIX-MILTER` if traffic testing fails. Backups also include rollback guidance.

**Quarantine difference:** in the Milter path, SpamGate requests an **MTA-side hold**. The raw quarantined message is **not retained by SpamGate**, so the Web UI's direct release button (for SMTP-spooled originals) is not available for those messages. To release a Postfix-held message, use verified Postfix queue tools and appropriate MTA permissions. A future native queue adapter must provide an audited, safe release operation; do not equate “quarantine verdict” with “SpamGate stored original.”

`non_smtpd_milters` is deliberately untouched. It handles locally submitted mail through a distinct Postfix path, which should be evaluated separately before enabling. Milter timeouts and failure behavior must be explicitly reviewed for the local Postfix version: **never assume fail-open**.

## ISPConfig / Postfix

Run SpamGate as a native service on the ISPConfig mail host, enable the loopback Milter, then use the read-only host inventory and `postconf -n` to review the active filtering configuration. **Do not run the automatic apply script.** ISPConfig can regenerate some mail-server configuration through upgrades/reconfiguration, so maintain any changes using the site's verified ISPConfig-supported persistence workflow and re-test after updates. In particular, check existing Rspamd/Amavis integration before introducing a second filter. This release does not provide an ISPConfig-specific persistent adapter or auto-migration.

## cPanel / WHM / Exim

The existing SpamGate Rspamd-style HTTP API does **not** prove that every Exim `spamd_address`/ACL command works with it. A tested, WHM-aware Exim ACL/spamd adapter is still required before changing real mail routing. The native executable can run on a cPanel host, but a running dashboard is **not** protection. cPanel/WHM specifically instructs administrators to use Exim Configuration Manager's Advanced Editor rather than directly editing `/etc/exim.conf`, which gets regenerated. No automatic cPanel configuration writes occur.

## Remote and Docker alternative

A dedicated remote or Docker SpamGate instance is appropriate only when a site's MTA has a tested, trusted private route to it. Ports are unchanged: management `38470`, Rspamd-style HTTP `38471`, Milter `38472`, SMTP `38473`, controller `38474`. Publish only the necessary interfaces. Docker is not required for local Postfix integration.

## Operational guardrails

- Do not uninstall or disable an existing spam filter until end-to-end tests, backups and a tested rollback exist.
- Milter and scan protocols are currently subsets, **not production-certified universal Rspamd replacements**.
- Keep the management listener accessible only from trusted administrators through firewall rules or an authenticated HTTPS proxy. Do not expose raw Milter or training listeners to the Internet.
- Source packages are developer artifacts, not signed native releases. Rebuild native binaries with a patched, currently supported Go version; do not use old unsigned Windows packages for production.

Upstream references: [Postfix Milter README](https://www.postfix.org/MILTER_README.html) and [cPanel Exim Configuration Manager](https://docs.cpanel.net/whm/service-configuration/exim-configuration-manager/).
