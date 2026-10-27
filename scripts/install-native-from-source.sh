#!/usr/bin/env bash
set -Eeuo pipefail

die() { printf 'SpamGate: %s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'HELP'
Usage: bash scripts/install-native-from-source.sh [--build-only]
Native Linux x86_64/ARM64 install. Run as a regular user from a Git checkout.
Downloads and SHA-256 verifies official Go 1.27.3 only if not already present.
Builds and tests SpamGate; by default installs the systemd service using sudo.
--build-only writes dist/native/spamgate and makes NO system modifications.
No Docker, chat ZIPs, automatic MTA edits, or service-port changes.
HELP
}
if [[ "$#" -eq 1 && "$1" == --help ]]; then usage; exit 0; fi
if [[ "$#" -gt 1 ]] || { [[ "$#" -eq 1 && "$1" != --build-only ]]; }; then usage >&2; exit 2; fi
[[ "$(uname -s)" == Linux ]] || die 'Linux only'
[[ "$(id -u)" != 0 ]] || die 'Run as an ordinary user, not root'
ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
[[ -f "$ROOT/go.mod" && -f "$ROOT/cmd/spamgate/main.go" ]] || die 'A complete SpamGate checkout is required'
for c in curl tar sha256sum mktemp install; do command -v "$c" >/dev/null || die "Missing: $c"; done
case "$(uname -m)" in
  x86_64|amd64)
    ARCH=amd64
    DIGEST=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40
    ;;
  aarch64|arm64)
    ARCH=arm64
    DIGEST=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49
    ;;
  *) die 'Only Linux x86_64 and ARM64 are supported' ;;
esac
WORK="$(mktemp -d /tmp/spamgate-native.XXXXXXXX)"
trap 'rm -rf -- "$WORK"' EXIT
GO=''
if command -v go >/dev/null && [[ "$(go env GOVERSION 2>/dev/null || :)" == go1.27.3 ]]; then
  GO="$(command -v go)"
else
  ARCHIVE="go1.27.3.linux-$ARCH.tar.gz"
  printf 'Downloading official Go 1.27.3 (%s)...\n' "$ARCH"
  curl --fail --location --show-error --silent --retry 3 --connect-timeout 20 --max-time 600 \
    "https://go.dev/dl/$ARCHIVE" -o "$WORK/$ARCHIVE" || die 'Go download failed'
  printf '%s  %s\n' "$DIGEST" "$WORK/$ARCHIVE" | sha256sum --check --status || die 'Go toolchain hash mismatch'
  tar -xzf "$WORK/$ARCHIVE" -C "$WORK"
  GO="$WORK/go/bin/go"
fi
[[ "$("$GO" version)" == *"go1.27.3 linux/"* ]] || die 'Incorrect Go toolchain'
export CGO_ENABLED=0 GOTOOLCHAIN=local
cd "$ROOT"
"$GO" test ./...
"$GO" vet ./...
mkdir -p "$WORK/package"
"$GO" build -trimpath -buildvcs=false -ldflags='-s -w' -o "$WORK/package/spamgate" ./cmd/spamgate
[[ "$("$WORK/package/spamgate" -version)" == 0.4.0-alpha.2 ]] || die 'Unexpected source version'
sha256sum "$WORK/package/spamgate"
if [[ "$#" -eq 1 && "$1" == --build-only ]]; then
  mkdir -p "$ROOT/dist/native"
  install -m 0755 "$WORK/package/spamgate" "$ROOT/dist/native/spamgate"
  printf 'Compiled: %s\n' "$ROOT/dist/native/spamgate"
  exit 0
fi
command -v sudo >/dev/null || die 'sudo required for systemd install; use --build-only to compile'
for name in install-linux.sh configure-postfix.sh; do
  [[ -f "$ROOT/scripts/$name" ]] || die "Missing $name"
  install -m 0755 "$ROOT/scripts/$name" "$WORK/package/$name"
done
printf 'Installing SpamGate service without changing Postfix/Exim/panel configuration...\n'
sudo "$WORK/package/install-linux.sh"
