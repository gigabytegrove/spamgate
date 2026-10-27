#!/usr/bin/env bash
set -Eeuo pipefail

fail() { printf 'SpamGate installation failed: %s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'USAGE'
Usage: sudo ./install-linux.sh [--listen HOST:PORT] [--no-local-milter] [--enable-local-milter]
Installs/upgrades the SpamGate binary as a systemd service.
The default management listener is 127.0.0.1:38470 (local only).
Existing configuration and mail history are retained on upgrades.
A new install enables a loopback-only Milter listener (port 38472); it NEVER
changes Postfix, ISPConfig, Exim, cPanel or another mail server automatically.
--no-local-milter disables that initial listener.
--enable-local-milter adds loopback-only Milter settings on existing installs.
USAGE
}

LISTEN=""
LOCAL_MILTER=auto
while (($#)); do
  case "$1" in
    --listen) (($# >= 2)) || fail '--listen requires HOST:PORT'; LISTEN="$2"; shift 2 ;;
    --no-local-milter) LOCAL_MILTER=no; shift ;;
    --enable-local-milter) LOCAL_MILTER=yes; shift ;;
    --help|-h) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done
[[ $EUID -eq 0 ]] || fail 'run this installer as root with sudo'
command -v systemctl >/dev/null || fail 'systemd/systemctl is required'
command -v id >/dev/null || fail 'id is required'
[[ -d /run/systemd/system ]] || fail 'systemd is not running as init'
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="$SCRIPT_DIR/spamgate"
[[ -f "$SOURCE" ]] || fail "SpamGate Linux binary not found beside installer: $SOURCE"
[[ -x "$SOURCE" ]] || fail "binary is not executable: $SOURCE"
HELPER="$SCRIPT_DIR/configure-postfix.sh"
[[ -r "$HELPER" ]] || fail "Native Postfix integration helper missing: $HELPER"
"$SOURCE" -version >/dev/null || fail 'binary failed its version check'

if [[ -n "$LISTEN" ]]; then
  [[ "$LISTEN" =~ ^[a-zA-Z0-9._:\[\]-]+$ ]] || fail 'invalid characters in --listen'
  [[ "$LISTEN" == *:* ]] || fail 'listener must include a port'
fi

if ! id spamgate >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/spamgate --shell /usr/sbin/nologin --user-group spamgate
fi
install -d -m 0700 -o spamgate -g spamgate /var/lib/spamgate
install -d -m 0750 -o root -g spamgate /etc/spamgate
CFG=/etc/spamgate/spamgate.env
if [[ ! -e "$CFG" ]]; then
  printf 'SPAMGATE_WEB_LISTEN=%s\n' "${LISTEN:-127.0.0.1:38470}" > "$CFG"
  if [[ "$LOCAL_MILTER" != no ]]; then
    printf 'SPAMGATE_MILTER_LISTEN=127.0.0.1:38472\nSPAMGATE_MILTER_TRUSTED_CIDRS=127.0.0.1/32\n' >> "$CFG"
  fi
  chown root:spamgate "$CFG"
  chmod 0640 "$CFG"
elif [[ -n "$LISTEN" ]]; then
  # Never wipe mail settings or existing secrets when changing the web listener.
  if grep -q '^SPAMGATE_WEB_LISTEN=' "$CFG"; then
    sed -i "s/^SPAMGATE_WEB_LISTEN=.*/SPAMGATE_WEB_LISTEN=$LISTEN/" "$CFG"
  else
    printf '\nSPAMGATE_WEB_LISTEN=%s\n' "$LISTEN" >> "$CFG"
  fi
fi
if [[ "$LOCAL_MILTER" == yes ]]; then
  if ! grep -q '^SPAMGATE_MILTER_LISTEN=' "$CFG"; then
    printf 'SPAMGATE_MILTER_LISTEN=127.0.0.1:38472\n' >> "$CFG"
  fi
  if ! grep -q '^SPAMGATE_MILTER_TRUSTED_CIDRS=' "$CFG"; then
    printf 'SPAMGATE_MILTER_TRUSTED_CIDRS=127.0.0.1/32\n' >> "$CFG"
  fi
fi

TMP_BIN="$(mktemp /usr/local/bin/.spamgate.XXXXXXXX)"
trap 'rm -f -- "$TMP_BIN"' EXIT
install -m 0755 "$SOURCE" "$TMP_BIN"
if systemctl is-active --quiet spamgate.service; then
  systemctl stop spamgate.service
fi
mv -f -- "$TMP_BIN" /usr/local/bin/spamgate
install -d -m 0755 /usr/local/libexec/spamgate
install -m 0755 "$HELPER" /usr/local/libexec/spamgate/configure-postfix
cat > /etc/systemd/system/spamgate.service <<'UNIT'
[Unit]
Description=SpamGate Mail Filtering and Management
Documentation=https://github.com/gigabytegrove/spamgate
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=spamgate
Group=spamgate
EnvironmentFile=-/etc/spamgate/spamgate.env
ExecStart=/usr/local/bin/spamgate -data /var/lib/spamgate
WorkingDirectory=/var/lib/spamgate
Restart=on-failure
RestartSec=5s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/spamgate
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LimitNOFILE=8192
TimeoutStopSec=30s

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 /etc/systemd/system/spamgate.service
systemctl daemon-reload
systemctl enable spamgate.service >/dev/null
systemctl start spamgate.service
systemctl is-active --quiet spamgate.service || fail 'service did not start; check journalctl -u spamgate'
printf '\nSpamGate installed.\n'
printf '  Service: systemctl status spamgate\n'
printf '  Setup key: sudo journalctl -u spamgate --no-pager -n 40\n'
printf '  Console: http://%s\n' "$(sed -n 's/^SPAMGATE_WEB_LISTEN=//p' "$CFG" | tail -n 1)"
printf '  Settings: /etc/spamgate/spamgate.env\n'
printf '  Persistent data: /var/lib/spamgate (kept on upgrades)\n'
printf '  No MTA configuration has been modified. Filtering starts only once you attach your MTA.\n'
printf '  Read-only inventory: sudo /usr/local/bin/spamgate -mailserver-report\n'
printf '  For standalone Postfix, review: sudo /usr/local/libexec/spamgate/configure-postfix --preview\n'
printf '  To change listener or mail settings, edit the env file and restart the service.\n'
