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
SOURCE_SHA="$(git rev-parse --verify HEAD)"
[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo 'Cannot attest exact source commit' >&2; exit 1; }
echo "QUALIFYING source $SOURCE_SHA / Go $GOVERSION / SpamGate $VERSION"

go test -count=1 ./...
# The race detector requires cgo even when callers set CGO_ENABLED=0 for release builds.
command -v cc >/dev/null || { echo "C compiler required for Go race tests (install build-essential)" >&2; exit 1; }
CGO_ENABLED=1 go test -race -p 1 -count=1 -timeout=15m ./...
go vet ./...
# Run hyphenated unittest files directly: unittest discovery silently reports 0 tests.
python3 scripts/test-spamgate-host-probe.py -v
python3 scripts/test-spamgate-host-probe-smtp.py -v
python3 scripts/test-spamgate-filtration-qualification.py -v
python3 scripts/test-spamgate-postfix-evidence.py -v
python3 scripts/test-spamgate-maildir-evidence.py -v
python3 scripts/test-native-systemd.py -v
bash -n scripts/deploy-native-worker.sh
python3 scripts/test-deploy-native-worker.py -v
python3 -m py_compile scripts/install-native-systemd.py
node --check internal/server/assets/app.js
node --test scripts/ui-regression.test.mjs
bash -n scripts/bootstrap-foreground.sh
bash -n scripts/migrate-native-launcher.sh
bash scripts/test-migrate-native-launcher.sh
bash scripts/test-supervised-updates.sh

# Number the actual compiled build after qualification, not the source tree.
# Local invocations default to manual a..z; CI explicitly requests automatic.
BUILD_KIND="${SPAMGATE_BUILD_KIND:-manual}"
[[ "$BUILD_KIND" == manual || "$BUILD_KIND" == automatic ]] || { echo 'SPAMGATE_BUILD_KIND must be manual or automatic' >&2; exit 64; }
BUILD_ARGS=(--mode "$BUILD_KIND" --out "$OUT")
if [[ -n "${SPAMGATE_BUILD_LETTER:-}" ]]; then BUILD_ARGS+=(--letter "$SPAMGATE_BUILD_LETTER"); fi
BUILD_VERSION="$(python3 "$ROOT/scripts/spamgate-build-id.py" "${BUILD_ARGS[@]}")"
[[ "$BUILD_VERSION" =~ ^[0-9]{8}-(0[0-9]|1[0-9]|2[0-3])[a-z]?$ ]] || { echo 'Build ID generator returned an invalid value' >&2; exit 1; }
LDFLAGS="-s -w -X github.com/gigabytegrove/spamgate/internal/core.BuildVersion=$BUILD_VERSION -X github.com/gigabytegrove/spamgate/internal/core.SourceCommit=$SOURCE_SHA"
echo "BUILD ID: $BUILD_VERSION ($BUILD_KIND; America/New_York), source $VERSION @ $SOURCE_SHA"
# Split native Linux layout, retaining legacy-compatible worker asset.
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags="$LDFLAGS" -o "$OUT/spamgate-worker-linux-amd64" ./cmd/spamgate
cp -p "$OUT/spamgate-worker-linux-amd64" "$OUT/spamgate-linux-amd64"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags="$LDFLAGS" -o "$OUT/spamgate-launcher-linux-amd64" ./cmd/spamgate-run
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags="$LDFLAGS -H=windowsgui" -o "$OUT/spamgate-windows-amd64.exe" ./cmd/spamgate
chmod 0755 "$OUT/spamgate-worker-linux-amd64" "$OUT/spamgate-linux-amd64" "$OUT/spamgate-launcher-linux-amd64"
test "$("$OUT/spamgate-worker-linux-amd64" -version)" = "$VERSION"
test "$("$OUT/spamgate-linux-amd64" -version)" = "$VERSION"
test "$("$OUT/spamgate-launcher-linux-amd64" -version)" = "$VERSION"
test "$("$OUT/spamgate-worker-linux-amd64" -build-version)" = "$BUILD_VERSION"
test "$("$OUT/spamgate-launcher-linux-amd64" -build-version)" = "$BUILD_VERSION"
python3 - "$OUT/BUILD-INFO.json" "$VERSION" "$BUILD_VERSION" "$SOURCE_SHA" "$BUILD_KIND" <<'PY'
import datetime, json, pathlib, sys
path,version,build,commit,kind=sys.argv[1:]
record={"version":version,"build_version":build,"source_commit":commit,"build_kind":kind,"time_zone":"America/New_York","qualified_at_utc":datetime.datetime.now(datetime.timezone.utc).isoformat()}
pathlib.Path(path).write_text(json.dumps(record,sort_keys=True,indent=2)+"\n",encoding="utf-8")
PY

cmp -s "$OUT/spamgate-worker-linux-amd64" "$OUT/spamgate-linux-amd64"
(cd "$OUT" && sha256sum spamgate-linux-amd64 spamgate-worker-linux-amd64 spamgate-launcher-linux-amd64 spamgate-windows-amd64.exe BUILD-INFO.json > SHA256SUMS.txt && sha256sum -c SHA256SUMS.txt)
for asset in spamgate-linux-amd64 spamgate-worker-linux-amd64 spamgate-launcher-linux-amd64 spamgate-windows-amd64.exe BUILD-INFO.json SHA256SUMS.txt; do test -s "$OUT/$asset" || exit 1; done
# Validate the actual release bytes, not just successful compilation.
# The fault-injection suite must reject a substituted launcher, missing asset,
# corrupted worker, manifest injection, wrong version and symlinked executable.
bash "$ROOT/scripts/test-native-release-assets.sh" "$OUT" "$VERSION"
printf 'All release gates passed. Build %s (%s), exact assets at %s\n' "$BUILD_VERSION" "$VERSION" "$OUT"
