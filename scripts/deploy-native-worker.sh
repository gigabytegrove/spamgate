#!/usr/bin/env bash
# Explicit native worker deployment for an already-installed SpamGate systemd
# service. Normal future releases use Settings > Software Updates.
# This command intentionally manages only SpamGate; it never edits the MTA,
# the permanent launcher or the persistent data directory.
set -Eeuo pipefail
umask 077

usage() {
  echo 'Usage: deploy-native-worker.sh --worker /absolute/path/to/binary --sha256 64hex --version X.Y.Z[-beta.N] [--root /opt/spamgate]' >&2
  exit 64
}
ROOT=/opt/spamgate
CANDIDATE=''
EXPECTED_SHA256=''
EXPECTED_VERSION=''
while (($#)); do
  case "$1" in
    --worker|--sha256|--version|--root)
      (($# >= 2)) || usage
      case "$1" in
        --worker) CANDIDATE=$2 ;;
        --sha256) EXPECTED_SHA256=$2 ;;
        --version) EXPECTED_VERSION=$2 ;;
        --root) ROOT=$2 ;;
      esac
      shift 2 ;;
    *) usage ;;
  esac
done
[[ "$CANDIDATE" == /* && "$ROOT" == /* && "$ROOT" != / && "$CANDIDATE" != "$ROOT/spamgate-worker" ]] || usage
[[ "$EXPECTED_SHA256" =~ ^[0-9a-f]{64}$ ]] || usage
[[ "$EXPECTED_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-((alpha|beta|rc)\.[0-9]+))?$ ]] || usage
if [[ "$ROOT" == /opt/spamgate && $EUID -ne 0 ]]; then
  echo 'The installed /opt/spamgate service requires root.' >&2; exit 1
fi
for tool in sha256sum systemctl curl ss flock mktemp install cp mv; do
  command -v "$tool" >/dev/null || { echo "Required command unavailable: $tool" >&2; exit 1; }
done
SERVICE=spamgate.service
LAUNCHER="$ROOT/spamgate"
WORKER="$ROOT/spamgate-worker"
DATA="$ROOT/data"
LOCK="$ROOT/.spamgate-worker-deploy.lock"
STAGED=''
BACKUP=''
CHANGED=0
RESTORED=0

rollback() {
  local rc=$?
  trap - EXIT INT TERM
  if [[ -n "$STAGED" ]]; then rm -f -- "$STAGED" || true; fi
  if ((rc != 0 && CHANGED == 1)); then
    echo 'ERROR: Worker update failed; restoring the previous executable and restarting SpamGate.' >&2
    systemctl stop "$SERVICE" || true
    if [[ -n "$BACKUP" && -s "$BACKUP" ]] && cp -p -- "$BACKUP" "$WORKER"; then
      RESTORED=1
      if systemctl start "$SERVICE"; then
        echo 'Rollback worker restored and service start requested. Verify mail flow.' >&2
      else
        echo 'CRITICAL: Previous worker restored but service restart failed.' >&2
      fi
    else
      echo "CRITICAL: Worker restoration failed; backup at $BACKUP" >&2
    fi
    systemctl --no-pager --full status "$SERVICE" || true
  fi
  exit "$rc"
}
trap rollback EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for path in "$ROOT" "$DATA"; do
  [[ -d "$path" && ! -L "$path" ]] || { echo "Unsafe or missing directory: $path" >&2; exit 1; }
done
for path in "$LAUNCHER" "$WORKER" "$CANDIDATE"; do
  [[ -f "$path" && ! -L "$path" && -x "$path" ]] || { echo "Missing or unsafe executable: $path" >&2; exit 1; }
done
[[ "$(readlink -f -- "$ROOT")" == "$ROOT" ]] || { echo 'Symlinked install root is unsafe.' >&2; exit 1; }

# This locks concurrent invocations but does not lock the running launcher.
exec 9>"$LOCK"
flock -n 9 || { echo 'Another worker deployment is already in progress.' >&2; exit 1; }

# Only take over the already-known SpamGate unit. A different service owning
# these ports is a security fault, not a reason to kill an unknown process.
EXECSTART="$(systemctl show "$SERVICE" --property=ExecStart --value)"
[[ "$EXECSTART" == *"path=$LAUNCHER ;"* && "$EXECSTART" == *"-data $DATA"* && "$EXECSTART" == *'-listen 0.0.0.0:38470'* ]] || {
  echo 'The SpamGate unit does not point to the locked launcher/data/listen configuration.' >&2
  exit 1
}
[[ "$("$CANDIDATE" -version)" == "$EXPECTED_VERSION" ]] || { echo 'Candidate version mismatch.' >&2; exit 1; }
[[ "$(sha256sum "$CANDIDATE" | cut -d ' ' -f 1)" == "$EXPECTED_SHA256" ]] || { echo 'Candidate SHA-256 mismatch.' >&2; exit 1; }
OLD_VERSION="$("$WORKER" -version)"
OLD_SHA256="$(sha256sum "$WORKER" | cut -d ' ' -f 1)"
LAUNCHER_SHA256="$(sha256sum "$LAUNCHER" | cut -d ' ' -f 1)"
[[ "$OLD_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-((alpha|beta|rc)\.[0-9]+))?$ ]] || {
  echo 'Existing worker version cannot be verified.' >&2; exit 1
}

health() {
  local response
  response="$(curl --noproxy '*' -fsS --connect-timeout 1 --max-time 2 http://127.0.0.1:38470/healthz 2>/dev/null)" || return 1
  [[ "$response" == *'"status":"ok"'* && "$response" == *"\"version\":\"$EXPECTED_VERSION\""* ]]
}
milter() {
  ss -H -ltnp '( sport = :38472 )' | grep -F '127.0.0.1:38472' | grep -Fq 'spamgate-worker'
}
verify() {
  for ((i=0;i<30;i++)); do
    if systemctl is-active --quiet "$SERVICE" && health && milter; then
      [[ "$("$WORKER" -version)" == "$EXPECTED_VERSION" ]] || return 1
      [[ "$(sha256sum "$LAUNCHER" | cut -d ' ' -f 1)" == "$LAUNCHER_SHA256" ]] || return 1
      return 0
    fi
    sleep 1
  done
  echo 'New worker did not provide verified HTTP and worker-owned Milter health.' >&2
  return 1
}

if [[ "$OLD_SHA256" == "$EXPECTED_SHA256" ]]; then
  echo "Verified worker already installed ($EXPECTED_VERSION). Checking or restarting its service."
  if ! systemctl is-active --quiet "$SERVICE" || ! health || ! milter; then
    systemctl restart "$SERVICE"
  fi
  verify
  echo "SUCCESS: SpamGate $EXPECTED_VERSION healthy; no binary replacement needed."
  exit 0
fi

BACKUP="$ROOT/spamgate-worker.before-${EXPECTED_VERSION}.$(date -u +%Y%m%dT%H%M%SZ).$$"
[[ ! -e "$BACKUP" ]] || { echo 'Backup path already exists.' >&2; exit 1; }
cp -p -- "$WORKER" "$BACKUP"
[[ -s "$BACKUP" && "$(sha256sum "$BACKUP" | cut -d ' ' -f 1)" == "$OLD_SHA256" ]] || {
  echo 'Failed to create exact backup of current worker.' >&2; exit 1
}
STAGED="$(mktemp "$ROOT/.spamgate-worker-staged.XXXXXXXX")"
install -m 0755 "$CANDIDATE" "$STAGED"
[[ "$(sha256sum "$STAGED" | cut -d ' ' -f 1)" == "$EXPECTED_SHA256" ]] || { echo 'Staging hash mismatch.' >&2; exit 1; }

echo "Upgrading SpamGate worker $OLD_VERSION -> $EXPECTED_VERSION; backing up to $BACKUP"
CHANGED=1
# Stopping the known unit is intentional. A live Milter is normal and must
# never cause the release-build tests or this service-aware upgrade to fail.
systemctl stop "$SERVICE"
mv -f -- "$STAGED" "$WORKER"
STAGED=''
systemctl start "$SERVICE"
verify
CHANGED=0
printf 'SUCCESS: %s deployed; launcher unchanged; data preserved; rollback: %s\n' "$EXPECTED_VERSION" "$BACKUP"
