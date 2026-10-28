# SpamGate native installation: Windows and Linux

**Preferred distribution:** self-contained native binary archives, without Docker, Node.js, a frontend build, or a database server.

> **Windows release hold (October 26, 2026):** Previously shared SpamGate v0.3.0-alpha.2 Windows archives were built using outdated Go 1.23.2 and were not code-signed or cleared by Defender. Do not treat those archives as production-ready downloads. A vetted, Go 1.27.3-or-newer build, Authenticode signature, and on-Windows package/service validation are required before public release. Do not disable Defender or override script execution policy to install an unverified build. The build script now creates explicitly labeled development archives only.

**Primary deployment:** a Go binary and systemd service installed directly on an existing Linux mail server. A fresh native installation enables a **loopback-only Milter listener** but does not modify the mail server. Follow [native mail server integration](NATIVE_MAIL_SERVERS.md) for panel-aware steps.

**Alternative deployment:** Docker Compose (see project README). Binaries embed the management UI.

## Requirements and security

- Linux x64/ARM64: systemd-based distribution with glibc or musl and network access for DNS authentication checks. Installer must be run as root; daemon runs under a dedicated unprivileged `spamgate` account.
- Windows x64/ARM64: Windows 10/11 or supported Windows Server, PowerShell 5.1+, administrator permission for service installation. Native Windows Service Control Manager registration uses `LocalService` (no third-party service wrapper).
- Default admin Web UI listener: `0.0.0.0:38470` (all IPv4 interfaces). Restrict TCP 38470 to trusted administrators with a firewall and/or authenticated HTTPS proxy. **Native Linux fresh installations enable only the loopback TCP Milter on port 38472; Docker and Windows still require explicit configuration.** No mail-server configuration is changed automatically. Use an HTTPS reverse proxy for remote console administration. Never send administrator credentials over unencrypted HTTP on public networks.
- Port 38471: Rspamd-style HTTP; 38472: Milter; 38473: SMTP filter; 38474: controller. Each requires explicit enablement and the documented trusted-CIDR/credential controls.
- Do not direct live production mail to SpamGate alpha until mail-flow and conformance testing is completed.

## Linux x64 or ARM64

Extract `spamgate_VERSION_linux-amd64.tar.gz` or `spamgate_VERSION_linux-arm64.tar.gz` and run in its extracted directory:

```bash
sudo ./install-linux.sh
sudo /usr/local/bin/spamgate -mailserver-report
sudo systemctl status spamgate --no-pager
sudo journalctl -u spamgate --no-pager -n 50
```

The one-time setup key is written to the systemd journal before admin creation. Open <http://127.0.0.1:38470> from the server's own browser, or configure a secured reverse proxy. For trusted LAN testing only, install with an explicit host address (the installer does **not** open your firewall):

```bash
sudo ./install-linux.sh --listen 192.168.1.10:38470
```

Paths: executable `/usr/local/bin/spamgate`, systemd unit `/etc/systemd/system/spamgate.service`, editable service environment `/etc/spamgate/spamgate.env`, data `/var/lib/spamgate` (permissions restricted). On an existing installation, enable the loopback Milter with `sudo ./install-linux.sh --enable-local-milter` from a verified native package. To opt out during a fresh install, use `--no-local-milter`. Attach Postfix only after read-only inspection: `sudo /usr/local/libexec/spamgate/configure-postfix --preview`. Hosting-panel managed configurations are never changed automatically.

To enable a mail listener, add its documented `SPAMGATE_*` environment variables to the service environment file and run `sudo systemctl restart spamgate`. **Changing `--listen` never removes other variables.**

**Update:** stop mail flow, back up the data directory, extract the newer archive, run `sudo ./install-linux.sh` again. The updater restarts the service and preserves history, policies, credentials, keys, models and quarantines. Check `/healthz` and the journal before restoring mail flow. Do not run multiple binaries against one data directory.

**Uninstall:** `sudo ./uninstall-linux.sh`. Data and environment files remain on disk. No installer automatically deletes the stored email data or service account.

## Windows x64 or ARM64

Once a signed, validated Windows release exists, extract the appropriate `windows-amd64` or `windows-arm64` archive. Confirm its SHA-256 digest against the independently published checksum and verify its Authenticode publisher signature. In an **elevated Windows PowerShell** window in the extracted directory:

```powershell
# After verifying the publisher's Authenticode signature and the SHA-256 digest:
.\install-windows.ps1
Get-Service -Name SpamGate
Get-Content "$env:ProgramData\SpamGate\spamgate.log" -Tail 30
```

Do **not** override an execution-policy denial with `-ExecutionPolicy Bypass`; resolve it via trusted, signed deployment procedures. The installer is optional for a local foreground test: use `spamgate.exe -version` and then the documented portable command. The native Windows service runs as `NT AUTHORITY\LocalService` and starts automatically at boot. Program location: `C:\Program Files\SpamGate\spamgate.exe`; data/logs: `C:\ProgramData\SpamGate`. The Windows ACL grants access only to SYSTEM, local Administrators, and LocalService. One-time claim key is in `spamgate.log`. The management console is available at <http://127.0.0.1:38470> on the Windows host.

To bind only to a trusted LAN interface (configure Windows Firewall separately):

```powershell
.\install-windows.ps1 -Listen '192.168.1.10:38470'
```

**Update:** stop production routing and back up `%ProgramData%\SpamGate`, extract the new matching architecture ZIP and rerun `install-windows.ps1` elevated. Existing listen settings persist if `-Listen` is not specified. The installer stops the service, replaces the executable and starts it again without deleting data.

**Uninstall:** `.\uninstall-windows.ps1` elevated. Existing data is intentionally **not** deleted.

## Manual portable use (both operating systems)

On Linux:

```bash
mkdir -p "$HOME/spamgate-data" && chmod 0700 "$HOME/spamgate-data"
./spamgate -data "$HOME/spamgate-data" -listen 0.0.0.0:38470
```

On Windows (PowerShell, interactive foreground session):

```powershell
.\spamgate.exe -data "$env:LOCALAPPDATA\SpamGate" -listen '0.0.0.0:38470'
```

The process runs in the foreground and stops on Ctrl+C. Service installation is recommended for unattended use.

## Docker alternative

The source repository includes `Dockerfile` and `compose.yaml`:

```bash
git clone https://github.com/gigabytegrove/spamgate.git
cd spamgate
docker compose up -d --build
docker compose logs spamgate --tail=60
```

The Compose profile explicitly binds the web listener to `0.0.0.0:38470` **inside** the container and maps host port 38470. The controller secret is only required when enabling the controller. Production Docker images must be built and validated separately before registry distribution is advertised.

## Release validation and reproducibility

Release maintainers can create four **unsigned development archives** and `SHA256SUMS.txt` with `bash scripts/build-release.sh` after satisfying the patched-Go toolchain guard. Builds are `CGO_ENABLED=0`, with UI assets compiled into the binaries. Verify package checksums before installing, confirm service logs contain no fatal startup errors, and run an actual Windows service integration smoke test before treating a Windows package as fully certified. The build script refuses to claim public release readiness. Production Windows signing must be performed with a verified publisher certificate; on-Windows signature verification, antivirus scanning, and end-to-end service smoke tests are separate required steps. It does not publish releases or use GitHub Actions. See `docs/RELEASE_SECURITY.md`.

**Not available in this alpha:** automatic in-UI binary updates, signed binaries/installers, MSI/MSIX or Debian/RPM packages, rollback automation, Windows native runtime smoke testing within Linux, and universal Rspamd production parity.
