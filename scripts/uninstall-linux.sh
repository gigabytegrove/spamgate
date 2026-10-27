#!/usr/bin/env bash
set -Eeuo pipefail
if ((EUID != 0)); then echo 'Run with sudo' >&2; exit 1; fi
if [[ $# -gt 0 ]]; then
  echo 'This uninstaller never deletes SpamGate data automatically. No arguments supported.' >&2
  exit 2
fi
if command -v systemctl >/dev/null; then
  systemctl disable --now spamgate.service 2>/dev/null || true
fi
rm -f /etc/systemd/system/spamgate.service /usr/local/bin/spamgate /usr/local/libexec/spamgate/configure-postfix
rmdir /usr/local/libexec/spamgate 2>/dev/null || true
if command -v systemctl >/dev/null; then systemctl daemon-reload; fi
printf '%s\n' 'SpamGate service and executable removed.' \
  'Existing settings remain in /etc/spamgate and mail history remains in /var/lib/spamgate.' \
  'No user account or stored data was deleted.'
