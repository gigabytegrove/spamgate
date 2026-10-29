#!/usr/bin/env bash
# One-time, explicit native migration: spamgate (old worker) ->
# spamgate (permanent supervisor) + spamgate-worker (updatable application).
# Never starts/stops an MTA or mutates the persistent data directory.
set -Eeuo pipefail
TAG='v0.6.0-alpha.16'
REPO='gigabytegrove/spamgate'
TARGET="${1:-/opt/spamgate}"
SOURCE="${2:-}"
[[ "$TARGET" == /* && "$TARGET" != / ]] || { echo 'Target must be an absolute non-root directory' >&2; exit 1; }
[[ -d "$TARGET" && -f "$TARGET/spamgate" ]] || { echo "Current SpamGate installation missing at $TARGET" >&2; exit 1; }
command -v sha256sum >/dev/null && command -v flock >/dev/null || { echo 'sha256sum and flock are required' >&2; exit 1; }
# Never replace a running launcher or application executable. /proc also catches
# processes started with no -listen flags and deleted-but-still-open binaries.
for proc in /proc/[0-9]*/exe; do
  [[ -L "$proc" ]] || continue
  executable="$(readlink "$proc" 2>/dev/null || true)"
  case "$executable" in
    "$TARGET/spamgate"|"$TARGET/spamgate (deleted)"|"$TARGET/spamgate-worker"|"$TARGET/spamgate-worker (deleted)"|"$TARGET/spamgate-run"|"$TARGET/spamgate-run (deleted)")
      echo "SpamGate process is running at $executable; stop it cleanly before migration" >&2; exit 1 ;;
  esac
done
if command -v ss >/dev/null && ss -ltn | grep -Eq ':(38470|38472)[[:space:]]'; then
  echo 'Management/Milter listener port is in use; refusing executable migration' >&2; exit 1
fi
exec 9>"$TARGET/.spamgate-native-migration.lock"
flock -n 9 || { echo 'Another SpamGate migration is running' >&2; exit 1; }
TEMP="$(mktemp -d "$TARGET/.spamgate-native-alpha16.XXXXXXXX")"
cleanup(){ rm -rf -- "$TEMP"; }
trap cleanup EXIT
if [[ -z "$SOURCE" ]]; then
  command -v gh >/dev/null || { echo 'Use gh auth login, or provide a local folder containing all 3 verified release files' >&2; exit 1; }
  gh release download "$TAG" --repo "$REPO" --dir "$TEMP" \
    --pattern 'spamgate-launcher-linux-amd64' \
    --pattern 'spamgate-worker-linux-amd64' \
    --pattern 'SHA256SUMS.txt'
  SOURCE="$TEMP"
fi
[[ -d "$SOURCE" ]] || { echo "Missing asset directory: $SOURCE" >&2; exit 1; }
for name in spamgate-launcher-linux-amd64 spamgate-worker-linux-amd64; do
  [[ -f "$SOURCE/$name" && ! -L "$SOURCE/$name" ]] || { echo "Missing regular release asset: $name" >&2; exit 1; }
  grep -Eq "^[[:xdigit:]]{64}[[:space:]]+${name}$" "$SOURCE/SHA256SUMS.txt" || { echo "Checksum entry missing for $name" >&2; exit 1; }
done
(cd "$SOURCE" && sha256sum --ignore-missing -c SHA256SUMS.txt)
install -m 0700 "$SOURCE/spamgate-launcher-linux-amd64" "$TEMP/launcher"
install -m 0700 "$SOURCE/spamgate-worker-linux-amd64" "$TEMP/worker"
[[ "$("$TEMP/launcher" -version)" == "${TAG#v}" ]] || { echo 'Wrong launcher version' >&2; exit 1; }
[[ "$("$TEMP/worker" -version)" == "${TAG#v}" ]] || { echo 'Wrong worker version' >&2; exit 1; }
old_version="$("$TARGET/spamgate" -version)"
[[ "$old_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]+)?$ ]] || { echo 'Current executable did not report a known version; refusing migration' >&2; exit 1; }
BACKUP="$TARGET/spamgate.pre-native-split-$old_version"
[[ ! -e "$BACKUP" && ! -e "$TARGET/spamgate-worker" && ! -L "$TARGET/spamgate" ]] || { echo 'Backup exists, new worker exists, or launcher path is a symlink; refusing migration' >&2; exit 1; }
cp -p -- "$TARGET/spamgate" "$BACKUP"
# Both staged files reside on TARGET's filesystem; each rename is atomic.
install -m 0755 "$TEMP/worker" "$TARGET/.spamgate-worker-alpha16.new"
install -m 0755 "$TEMP/launcher" "$TARGET/.spamgate-launcher-alpha16.new"
mv -T -- "$TARGET/.spamgate-worker-alpha16.new" "$TARGET/spamgate-worker"
mv -T -- "$TARGET/.spamgate-launcher-alpha16.new" "$TARGET/spamgate"
[[ "$("$TARGET/spamgate" -version)" == "${TAG#v}" ]] || { echo 'Launcher did not report expected version' >&2; exit 1; }
[[ "$("$TARGET/spamgate-worker" -version)" == "${TAG#v}" ]] || { echo 'Worker did not report expected version' >&2; exit 1; }
echo "Migration complete: $TARGET/spamgate is the supervisor; $TARGET/spamgate-worker is the updatable application."
echo "Previous standalone application preserved at $BACKUP"
echo 'Your data directory and Postfix configuration were not modified.'
echo "Start: cd '$TARGET' && ./spamgate -data '$TARGET/data' -listen 0.0.0.0:38470"