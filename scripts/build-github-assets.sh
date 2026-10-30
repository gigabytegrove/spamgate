#!/usr/bin/env bash
# Native, no-GitHub-Actions release qualification: produces the exact immutable
# GitHub assets used by the native foreground updater. Run on dockeradm.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT="${1:-$ROOT/dist-native}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
command -v go >/dev/null || { echo 'Go toolchain required' >&2; exit 1; }
command -v node >/dev/null || { echo 'Node.js required for UI regression tests' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'Python3 required for supervisor integration tests' >&2; exit 1; }
command -v sha256sum >/dev/null || { echo 'sha256sum required' >&2; exit 1; }
# Select a patched toolchain automatically without changing the host installation.
# Go 1.21+ supports secure, checksum-database-verified toolchain downloads via
# GOTOOLCHAIN. In particular, dockeradm currently has go1.26.8: do not build
# security-sensitive releases using that older standard library.
required_go="go1.27.3"
patched_go() {
  local version="$1"
  [[ "$version" =~ ^go([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || return 1
  local major="${BASH_REMATCH[1]}" minor="${BASH_REMATCH[2]}" patch="${BASH_REMATCH[3]}"
  (( major > 1 || (major == 1 && (minor > 27 || (minor == 27 && patch >= 3))) ))
}

GOVERSION="$(go env GOVERSION)" || { echo 'Unable to query Go toolchain' >&2; exit 1; }
if ! patched_go "$GOVERSION"; then
  echo "Local Go $GOVERSION is below patched release baseline $required_go."
  echo "Selecting $required_go using the Go toolchain manager (no system-wide install)."
  if [[ "$(go env GOSUMDB)" == off ]]; then
    echo 'Cannot securely fetch Go toolchain while GOSUMDB=off. Refusing release.' >&2
    exit 1
  fi
  export GOTOOLCHAIN="$required_go"
  if ! GOVERSION="$(go env GOVERSION)"; then
    echo "Unable to obtain verified $required_go toolchain. Check outbound Go module proxy/checksum DB access." >&2
    exit 1
  fi
fi
patched_go "$GOVERSION" || {
  echo "Refusing release from unsupported Go toolchain $GOVERSION; requires $required_go or later." >&2
  exit 1
}
echo "Release compiler: $(go version) (GOTOOLCHAIN=${GOTOOLCHAIN:-auto})"
VERSION="$(go run ./cmd/spamgate -version)"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+-(alpha|beta|rc)\.[0-9]+$ ]] || { echo "Invalid development version: $VERSION" >&2; exit 1; }
echo "QUALIFYING source $(git rev-parse HEAD 2>/dev/null || echo source-tree) / Go $GOVERSION / SpamGate $VERSION"

go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
node --check internal/server/assets/app.js
node --test scripts/ui-regression.test.mjs
bash -n scripts/bootstrap-foreground.sh
bash -n scripts/migrate-native-launcher.sh
bash scripts/test-migrate-native-launcher.sh
bash scripts/test-supervised-updates.sh

# Split native Linux layout, retaining legacy-compatible worker asset.
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$OUT/spamgate-worker-linux-amd64" ./cmd/spamgate
cp -p "$OUT/spamgate-worker-linux-amd64" "$OUT/spamgate-linux-amd64"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$OUT/spamgate-launcher-linux-amd64" ./cmd/spamgate-run
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags='-s -w -H=windowsgui' -o "$OUT/spamgate-windows-amd64.exe" ./cmd/spamgate
chmod 0755 "$OUT/spamgate-worker-linux-amd64" "$OUT/spamgate-linux-amd64" "$OUT/spamgate-launcher-linux-amd64"
test "$("$OUT/spamgate-worker-linux-amd64" -version)" = "$VERSION"
test "$("$OUT/spamgate-linux-amd64" -version)" = "$VERSION"
test "$("$OUT/spamgate-launcher-linux-amd64" -version)" = "$VERSION"
cmp -s "$OUT/spamgate-worker-linux-amd64" "$OUT/spamgate-linux-amd64"
(cd "$OUT" && sha256sum spamgate-linux-amd64 spamgate-worker-linux-amd64 spamgate-launcher-linux-amd64 spamgate-windows-amd64.exe > SHA256SUMS.txt && sha256sum -c SHA256SUMS.txt)
for asset in spamgate-linux-amd64 spamgate-worker-linux-amd64 spamgate-launcher-linux-amd64 spamgate-windows-amd64.exe SHA256SUMS.txt; do test -s "$OUT/$asset" || exit 1; done
printf 'All release gates passed. Exact assets at %s\n' "$OUT"
