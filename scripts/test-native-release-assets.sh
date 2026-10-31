#!/usr/bin/env bash
# Fault-injection regression using the exact compiled assets. Never contacts GitHub.
set -Eeuo pipefail
if [[ $# -ne 2 ]]; then echo 'Usage: test-native-release-assets.sh ASSET_DIRECTORY VERSION' >&2; exit 64; fi
SOURCE="$(cd "$1" && pwd -P)"
VERSION="$2"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-native-release-assets.sh"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
prepare() {
  rm -rf -- "$TMP/assets"
  mkdir -p "$TMP/assets"
  cp -p -- "$SOURCE"/spamgate-{launcher,worker}-linux-amd64 "$SOURCE/spamgate-linux-amd64" "$SOURCE/spamgate-windows-amd64.exe" "$SOURCE/SHA256SUMS.txt" "$TMP/assets/"
}
reject() {
  local label="$1"
  if bash "$VERIFY" "$TMP/assets" "$VERSION" >"$TMP/output" 2>&1; then
    echo "FAIL: $label was accepted" >&2; cat "$TMP/output" >&2; exit 1
  fi
  echo "PASS rejected: $label"
}
prepare
bash "$VERIFY" "$TMP/assets" "$VERSION"
prepare; printf '\001' | dd of="$TMP/assets/spamgate-worker-linux-amd64" bs=1 seek=100 conv=notrunc status=none; reject 'tampered worker'
prepare; cp -p "$TMP/assets/spamgate-worker-linux-amd64" "$TMP/assets/spamgate-launcher-linux-amd64"; (cd "$TMP/assets" && sha256sum spamgate-launcher-linux-amd64 > launcher.sum && sed -i "/ spamgate-launcher-linux-amd64$/d" SHA256SUMS.txt && cat launcher.sum >> SHA256SUMS.txt); reject 'worker substituted for launcher'
prepare; printf '%s\n' "$(sha256sum "$TMP/assets/spamgate-worker-linux-amd64" | cut -d' ' -f1)  spamgate-worker-linux-amd64" >> "$TMP/assets/SHA256SUMS.txt"; reject 'duplicate manifest entry'
prepare; sed -i 's@spamgate-worker-linux-amd64@../spamgate-worker-linux-amd64@' "$TMP/assets/SHA256SUMS.txt"; reject 'path traversal in manifest'
prepare; rm "$TMP/assets/spamgate-launcher-linux-amd64"; reject 'missing launcher'
prepare; if bash "$VERIFY" "$TMP/assets" '0.6.0-beta.9999' >"$TMP/output" 2>&1; then echo 'FAIL: wrong version accepted' >&2; exit 1; fi; echo 'PASS rejected: wrong version'
prepare; ln -s "$SOURCE/spamgate-worker-linux-amd64" "$TMP/assets/spamgate-worker-linux-amd64.tmp"; mv -f "$TMP/assets/spamgate-worker-linux-amd64.tmp" "$TMP/assets/spamgate-worker-linux-amd64"; reject 'symlink worker'
echo 'PASS native release asset negative regression suite'
