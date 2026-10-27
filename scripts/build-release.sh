#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"
command -v go >/dev/null || { echo 'Go is required' >&2; exit 2; }
# Release binaries must be built with a supported security-patched Go toolchain.
# The minimum is intentionally explicit and must be reviewed when new Go
# security updates are published. Unpatched builds must not be distributed.
GOVERSION="$(go env GOVERSION)"
if [[ ! "$GOVERSION" =~ ^go([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "STOP: Cannot verify stable Go toolchain version: $GOVERSION" >&2
  exit 2
fi
major="${BASH_REMATCH[1]}"
minor="${BASH_REMATCH[2]}"
patch="${BASH_REMATCH[3]}"
if (( major < 1 || (major == 1 && (minor < 27 || (minor == 27 && patch < 3))) )); then
  echo "STOP: $GOVERSION is older than the required patched Go 1.27.3." >&2
  echo 'Install an up-to-date, supported Go release from https://go.dev/dl/ and rebuild.' >&2
  exit 2
fi
# This script builds developer verification packages, not trusted Windows
# releases. Authenticode signing and a real Defender scan must be completed
# on a Windows release machine before publication.
if [[ "${SPAMGATE_RELEASE_CHANNEL:-development}" != development ]]; then
  echo 'STOP: Public Windows release signing/verification is not configured.' >&2
  echo 'Do not publish unsigned or Defender-unverified executables.' >&2
  exit 2
fi
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
  base="spamgate_${VERSION}_${platform}_UNSIGNED-DEVELOPMENT"
  tmp="$(mktemp -d)"
  case "$os" in
    linux)
      GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$tmp/spamgate" ./cmd/spamgate
      install -m 0755 scripts/install-linux.sh scripts/uninstall-linux.sh scripts/configure-postfix.sh "$tmp/"
      cp docs/INSTALLATION.md "$tmp/INSTALLATION.md"
      tar -C "$tmp" -czf "$OUT/$base.tar.gz" .
      ;;
    windows)
      GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags='-s -w -H=windowsgui' -o "$tmp/spamgate.exe" ./cmd/spamgate
      cp scripts/install-windows.ps1 scripts/uninstall-windows.ps1 docs/INSTALLATION.md "$tmp/"
      (cd "$tmp" && zip -q -X -r "$OUT/$base.zip" .)
      ;;
  esac
  rm -rf "$tmp"
  printf 'Built %s\n' "$base"
done
(cd "$OUT" && sha256sum ./*.tar.gz ./*.zip > SHA256SUMS.txt)
printf 'UNSIGNED DEVELOPMENT packages only (not cleared for public distribution): %s\n' "$OUT"
