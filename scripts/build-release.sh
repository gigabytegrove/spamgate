#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"
command -v go >/dev/null || { echo 'Go is required' >&2; exit 2; }
command -v zip >/dev/null || { echo 'zip is required for Windows archives' >&2; exit 2; }
command -v sha256sum >/dev/null || { echo 'sha256sum is required' >&2; exit 2; }
VERSION="$(go run ./cmd/spamgate -version)"
[[ "$VERSION" =~ ^[A-Za-z0-9._-]+$ ]] || { echo 'Invalid version' >&2; exit 2; }
OUT="${1:-$ROOT/dist}"
mkdir -p -- "$OUT"
OUT="$(cd "$OUT" && pwd)"
export CGO_ENABLED=0
printf 'Testing SpamGate before packaging...\n'
go test ./...
go vet ./...
for platform in linux-amd64 linux-arm64 windows-amd64 windows-arm64; do
  os="${platform%-*}"
  arch="${platform#*-}"
  base="spamgate_${VERSION}_${platform}"
  tmp="$(mktemp -d)"
  case "$os" in
    linux)
      GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$tmp/spamgate" ./cmd/spamgate
      install -m 0755 scripts/install-linux.sh scripts/uninstall-linux.sh "$tmp/"
      cp docs/INSTALLATION.md "$tmp/INSTALLATION.md"
      tar -C "$tmp" -czf "$OUT/$base.tar.gz" .
      ;;
    windows)
      GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$tmp/spamgate.exe" ./cmd/spamgate
      cp scripts/install-windows.ps1 scripts/uninstall-windows.ps1 docs/INSTALLATION.md "$tmp/"
      (cd "$tmp" && zip -q -X -r "$OUT/$base.zip" .)
      ;;
  esac
  rm -rf "$tmp"
  printf 'Built %s\n' "$base"
done
(cd "$OUT" && sha256sum ./*.tar.gz ./*.zip > SHA256SUMS.txt)
printf 'Release packages in %s\n' "$OUT"
