#!/usr/bin/env bash
# Verify exactly the native Linux release contract before any publication.
set -Eeuo pipefail
export LC_ALL=C
if [[ $# -ne 2 ]]; then
  echo 'Usage: verify-native-release-assets.sh ASSET_DIRECTORY VERSION' >&2
  exit 64
fi
DIR="$1"
VERSION="$2"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+-(alpha|beta|rc)\.[0-9]+$ ]] || {
  echo "Invalid prerelease version: $VERSION" >&2; exit 64;
}
[[ -d "$DIR" && ! -L "$DIR" ]] || { echo 'Asset directory must be a real directory' >&2; exit 1; }
DIR="$(cd -- "$DIR" && pwd -P)"
ASSETS=(spamgate-launcher-linux-amd64 spamgate-worker-linux-amd64 spamgate-linux-amd64 spamgate-windows-amd64.exe)
MANIFEST="$DIR/SHA256SUMS.txt"
[[ -f "$MANIFEST" && ! -L "$MANIFEST" ]] || { echo 'Missing regular SHA256SUMS.txt' >&2; exit 1; }
for asset in "${ASSETS[@]}"; do
  [[ -f "$DIR/$asset" && ! -L "$DIR/$asset" ]] || { echo "Missing or unsafe release asset: $asset" >&2; exit 1; }
  [[ $(stat -c '%s' "$DIR/$asset") -ge 4096 ]] || { echo "Truncated release asset: $asset" >&2; exit 1; }
done
declare -A SEEN=()
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ "$line" =~ ^([0-9a-fA-F]{64})\ \ ([A-Za-z0-9._-]+)$ ]] || {
    echo 'Malformed checksum manifest line' >&2; exit 1;
  }
  name="${BASH_REMATCH[2]}"
  case "$name" in
    spamgate-launcher-linux-amd64|spamgate-worker-linux-amd64|spamgate-linux-amd64|spamgate-windows-amd64.exe) ;;
    *) echo "Unexpected manifest entry: $name" >&2; exit 1 ;;
  esac
  [[ -z "${SEEN[$name]:-}" ]] || { echo "Duplicate manifest entry: $name" >&2; exit 1; }
  SEEN[$name]=1
done < "$MANIFEST"
[[ ${#SEEN[@]} -eq ${#ASSETS[@]} ]] || { echo 'Incomplete checksum manifest' >&2; exit 1; }
(cd "$DIR" && sha256sum --check --strict --status SHA256SUMS.txt) || {
  echo 'Release checksum verification failed' >&2; exit 1;
}
cmp -s "$DIR/spamgate-worker-linux-amd64" "$DIR/spamgate-linux-amd64" || {
  echo 'Legacy Linux worker must be byte-identical to native worker' >&2; exit 1;
}
! cmp -s "$DIR/spamgate-launcher-linux-amd64" "$DIR/spamgate-worker-linux-amd64" || {
  echo 'Launcher and worker must be independent executables' >&2; exit 1;
}
for asset in spamgate-launcher-linux-amd64 spamgate-worker-linux-amd64 spamgate-linux-amd64; do
  [[ "$(head -c 4 "$DIR/$asset" | od -An -tx1 | tr -d ' \n')" == '7f454c46' ]] || {
    echo "Not an ELF executable: $asset" >&2; exit 1;
  }
  [[ -x "$DIR/$asset" ]] || { echo "Linux executable is not executable: $asset" >&2; exit 1; }
  actual="$(timeout 10s "$DIR/$asset" -version)" || { echo "Cannot execute version probe: $asset" >&2; exit 1; }
  [[ "$actual" == "$VERSION" ]] || { echo "Wrong version for $asset: $actual (expected $VERSION)" >&2; exit 1; }
done
[[ "$(head -c 2 "$DIR/spamgate-windows-amd64.exe")" == 'MZ' ]] || {
  echo 'Windows release is not PE/MZ' >&2; exit 1;
}
echo "PASS native release assets: $VERSION, four binaries, exact hashes, independent launcher and worker"
