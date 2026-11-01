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
ASSETS=(spamgate-launcher-linux-amd64 spamgate-worker-linux-amd64 spamgate-linux-amd64 spamgate-windows-amd64.exe BUILD-INFO.json)
MANIFEST="$DIR/SHA256SUMS.txt"
[[ -f "$MANIFEST" && ! -L "$MANIFEST" ]] || { echo 'Missing regular SHA256SUMS.txt' >&2; exit 1; }
for asset in "${ASSETS[@]}"; do
  [[ -f "$DIR/$asset" && ! -L "$DIR/$asset" ]] || { echo "Missing or unsafe release asset: $asset" >&2; exit 1; }
  if [[ "$asset" != BUILD-INFO.json ]]; then
    [[ $(stat -c '%s' "$DIR/$asset") -ge 4096 ]] || { echo "Truncated release asset: $asset" >&2; exit 1; }
  fi
done
declare -A SEEN=()
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ "$line" =~ ^([0-9a-fA-F]{64})\ \ ([A-Za-z0-9._-]+)$ ]] || {
    echo 'Malformed checksum manifest line' >&2; exit 1;
  }
  name="${BASH_REMATCH[2]}"
  case "$name" in
    spamgate-launcher-linux-amd64|spamgate-worker-linux-amd64|spamgate-linux-amd64|spamgate-windows-amd64.exe|BUILD-INFO.json) ;;
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
# Validate build identity against executable flags, not a mutable filename.
BUILD_ID="$(python3 - "$DIR/BUILD-INFO.json" "$VERSION" <<'PY'
import datetime as dt, json, pathlib, re, sys
p, version=sys.argv[1:]
data=json.loads(pathlib.Path(p).read_text(encoding="utf-8"))
build=data.get("build_version")
kind=data.get("build_kind")
source=data.get("source_commit")
if data.get("version")!=version or not isinstance(build,str) or not re.fullmatch(r"[0-9]{8}-(?:[01][0-9]|2[0-3])[a-z]?",build):
    raise SystemExit("Invalid version or build ID in release manifest")
try: dt.datetime.strptime(build[:8],"%Y%m%d")
except ValueError: raise SystemExit("Invalid build calendar date")
if kind not in ("manual","automatic") or (kind=="manual") != build[-1].islower():
    raise SystemExit("Build mode and manual suffix do not agree")
if data.get("time_zone")!="America/New_York" or not re.fullmatch(r"[0-9a-f]{40}", str(source)):
    raise SystemExit("Release metadata lacks verified origin")
print(build)
PY
)" || exit 1
[[ "$("$DIR/spamgate-worker-linux-amd64" -build-version)" == "$BUILD_ID" ]] || { echo 'Worker build ID differs from manifest' >&2; exit 1; }
[[ "$("$DIR/spamgate-launcher-linux-amd64" -build-version)" == "$BUILD_ID" ]] || { echo 'Launcher build ID differs from manifest' >&2; exit 1; }
WORKER_COMMIT="$("$DIR/spamgate-worker-linux-amd64" -build-info | python3 -c 'import json,sys; print(json.load(sys.stdin)["source_commit"])')" || exit 1
MANIFEST_COMMIT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_commit"])' "$DIR/BUILD-INFO.json")" || exit 1
[[ "$WORKER_COMMIT" == "$MANIFEST_COMMIT" ]] || { echo 'Worker commit differs from manifest' >&2; exit 1; }

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
echo "PASS native release assets: $VERSION build $BUILD_ID, four binaries, signed-by-checksum metadata and independent launcher/worker"
