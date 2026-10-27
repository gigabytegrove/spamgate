# SpamGate 0.4.0-alpha.2 — native-first Linux integration

## Delivered

- Read-only Linux host inventory (`spamgate -mailserver-report` and admin-only `/api/v1/host`) detects Postfix/Exim and ISPConfig/cPanel/Plesk/DirectAdmin markers, reports existing milters and TCP listener readiness without changing configuration.
- Native Linux installer defaults to local-only management and Milter listeners. No changes to `/etc/postfix`, `/etc/exim.conf`, panel templates, firewall, or existing MTA services.
- Explicit opt-in configuration helper for **unmanaged** Postfix: preview by default, refusal on hosting panels, confirmation, existing-milter preservation, backups, Postfix validation, reload and restoration attempt on failure; detach only SpamGate's listener.
- Installer embeds the helper in `/usr/local/libexec/spamgate/` and retains settings, history and queue data across upgrades. Docker is optional and unchanged except its development image tag.
- Web UI Mail integrations page presents detected native MTA/panel, endpoint readiness, proposed Postfix parameters and limitations.
- Source tests for host identification, preserved milters, cPanel/Exim precedence, read-only preview, unauthenticated API access, Linux build/startup and basic TCP Milter reachability.

## Deferred / not certified

This release does **not** include a production-qualified Exim/WHM adapter, ISPConfig-managed config integration, native Postfix queue hold/release controls, universal Rspamd parity or real production-MTA testing. Do not enable this alpha for critical mail traffic. Native Linux builds made with Go 1.23.2 in the development environment are **not production release binaries**; rebuild and validate with a current supported patched Go toolchain.

## Upgrade

Native installation is the primary route. Deploy a verified Linux binary together with `install-linux.sh` and `configure-postfix.sh`, then inspect with `sudo spamgate -mailserver-report`. Upgrades do not silently enable mail filtering on an existing installation. Read [NATIVE_MAIL_SERVERS.md](NATIVE_MAIL_SERVERS.md) for host-specific steps and rollback.
