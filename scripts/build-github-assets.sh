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
VERSION="$(go run ./cmd/spamgate -version)"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+-alpha\.[0-9]+$ ]] || { echo "Invalid development version: $VERSION" >&2; exit 1; }
GOVERSION="$(go env GOVERSION)"
echo "QUALIFYING source $(git rev-parse HEAD 2>/dev/null || echo source-tree) / Go $GOVERSION / SpamGate $VERSION"
if [[ "$GOVERSION" =~ ^go([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  major="${BASH_REMATCH[1]}"; minor="${BASH_REMATCH[2]}"; patch="${BASH_REMATCH[3]}"
  if (( major < 1 || (major==1 && (minor < 27 || (minor==27 && patch < 3))) )); then
    echo 'Refusing release from a Go toolchain older than the project patched baseline 1.27.3' >&2; exit 1
  fi
else
  echo "Cannot verify patched Go version $GOVERSION" >&2;exit 1
fi

go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
node --check internal/server/assets/app.js
node --test scripts/ui-regression.test.mjs
bash -n scripts/bootstrap-foreground.sh
bash scripts/test-supervised-updates.sh

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$OUT/spamgate-linux-amd64" ./cmd/spamgate
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$OUT/spamgate-run-linux-amd64" ./cmd/spamgate-run
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags='-s -w -H=windowsgui' -o "$OUT/spamgate-windows-amd64.exe" ./cmd/spamgate
chmod 0755 "$OUT/spamgate-linux-amd64" "$OUT/spamgate-run-linux-amd64"
test "$("$OUT/spamgate-linux-amd64" -version)" = "$VERSION"
test "$("$OUT/spamgate-run-linux-amd64" -version)" = "$VERSION"
(cd "$OUT" && sha256sum spamgate-linux-amd64 spamgate-run-linux-amd64 spamgate-windows-amd64.exe > SHA256SUMS.txt && sha256sum -c SHA256SUMS.txt)
for asset in spamgate-linux-amd64 spamgate-run-linux-amd64 spamgate-windows-amd64.exe SHA256SUMS.txt; do test -s "$OUT/$asset" || exit 1;done
printf 'All release gates passed. Exact assets at %s\n' "$OUT"
