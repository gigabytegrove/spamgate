#!/usr/bin/env bash
# One-time adoption of the independent SpamGate native process supervisor.
# Does not change Postfix, firewall, SMTP/Milter env, history, or data files.
set -Eeuo pipefail
REPO="gigabytegrove/spamgate"
TAG="v0.6.0-alpha.13"
TARGET="${1:-/opt/spamgate}"
[[ "$TARGET" = /* && "$TARGET" != / ]] || { echo 'Target must be an absolute directory' >&2; exit 1; }
[[ -d "$TARGET" ]] || { echo "Missing installation: $TARGET" >&2; exit 1; }
[[ -f "$TARGET/spamgate" ]] || { echo "Existing worker missing: $TARGET/spamgate" >&2; exit 1; }
command -v curl >/dev/null && command -v sha256sum >/dev/null && command -v flock >/dev/null || { echo 'Requires curl, sha256sum and flock' >&2; exit 1; }
# This script intentionally requires the worker to have been stopped manually.
# A foreground operator can then see startup, replacement and rollback logs.
if pgrep -f '[s]pamgate[ -].*-listen.*38470' >/dev/null 2>&1 || (command -v ss >/dev/null && ss -ltn | grep -Eq ':38470[[:space:]]'); then
  echo 'SpamGate may still be running or port 38470 is occupied; refusing to replace executable' >&2
  exit 1
fi
exec 9>"$TARGET/.spamgate-bootstrap.lock"
flock -n 9 || { echo 'Another bootstrap is running' >&2; exit 1; }
TMP="$(mktemp -d "$TARGET/.spamgate-bootstrap.XXXXXXXX")"
cleanup(){ rm -rf -- "$TMP"; }
trap cleanup EXIT
URL="https://github.com/$REPO/releases/download/$TAG"
for name in SHA256SUMS.txt spamgate-linux-amd64 spamgate-run-linux-amd64; do
  curl -fLsS --retry 3 "$URL/$name" -o "$TMP/$name"
done
for name in spamgate-linux-amd64 spamgate-run-linux-amd64; do
  grep -Eq "^[[:xdigit:]]{64}[[:space:]]+${name}$" "$TMP/SHA256SUMS.txt" || { echo "Missing checksum for $name" >&2; exit 1; }
done
(cd "$TMP" && sha256sum --ignore-missing -c SHA256SUMS.txt)
chmod 0700 "$TMP/spamgate-linux-amd64" "$TMP/spamgate-run-linux-amd64"
test "$("$TMP/spamgate-linux-amd64" -version)" = "${TAG#v}" || { echo 'Wrong worker binary version' >&2; exit 1; }
test "$("$TMP/spamgate-run-linux-amd64" -version)" = "${TAG#v}" || { echo 'Wrong runner version' >&2; exit 1; }
OLD_VERSION="$($TARGET/spamgate -version)"
BACKUP="$TARGET/spamgate.before-independent-runner-$OLD_VERSION"
[[ ! -e "$BACKUP" ]] || { echo "Backup already exists ($BACKUP); refusing to overwrite" >&2; exit 1; }
cp -p -- "$TARGET/spamgate" "$BACKUP"
# All replacement files are staged in the same filesystem as the installation
# and renamed only after checksum and executable-version verification.
install -m 0700 "$TMP/spamgate-linux-amd64" "$TARGET/.spamgate-worker-new"
install -m 0700 "$TMP/spamgate-run-linux-amd64" "$TARGET/.spamgate-run-new"
mv -f -- "$TARGET/.spamgate-run-new" "$TARGET/spamgate-run"
mv -f -- "$TARGET/.spamgate-worker-new" "$TARGET/spamgate"
echo "Installed two SpamGate binaries: $TARGET/spamgate-run (stable supervisor), $TARGET/spamgate (updatable worker)"
echo "Old worker preserved: $BACKUP"
echo "Existing data and legacy .spamgate-backup remain unchanged."
echo 'Start your original foreground environment with ./spamgate-run instead of ./spamgate.'
