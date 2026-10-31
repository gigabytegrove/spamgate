#!/usr/bin/env bash
# The authoritative local, explicit native release publisher. Never installs or restarts SpamGate.
set -Eeuo pipefail
export LC_ALL=C
if [[ $# -ne 3 ]]; then
  echo 'Usage: publish-native-release.sh ASSET_DIRECTORY VERSION EXPECTED_MAIN_SHA' >&2
  exit 64
fi
ASSET_DIR="$1"
VERSION="$2"
EXPECTED_SHA="$3"
REPO='gigabytegrove/spamgate'
TAG="v$VERSION"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
[[ "$EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo 'Expected SHA must be a complete lowercase 40-character commit SHA' >&2; exit 64; }
[[ "${SPAMGATE_PUBLISH_CONFIRM:-}" == "$TAG@$EXPECTED_SHA" ]] || {
  echo "Refusing release: set SPAMGATE_PUBLISH_CONFIRM='$TAG@$EXPECTED_SHA' to explicitly authorize publication" >&2
  exit 64
}
command -v git >/dev/null && command -v gh >/dev/null || { echo 'git and gh are required' >&2; exit 1; }
cd "$ROOT"
[[ "$(git branch --show-current)" == main ]] || { echo 'Must publish from main' >&2; exit 1; }
[[ "$(git rev-parse HEAD)" == "$EXPECTED_SHA" ]] || { echo 'Local HEAD does not match expected SHA' >&2; exit 1; }
[[ -z "$(git status --porcelain --untracked-files=no)" ]] || { echo 'Tracked source has uncommitted changes' >&2; exit 1; }
REMOTE_SHA="$(git ls-remote origin refs/heads/main | awk '{print $1}')"
[[ "$REMOTE_SHA" == "$EXPECTED_SHA" ]] || { echo "Remote main moved: $REMOTE_SHA" >&2; exit 1; }
[[ -z "$(git ls-remote --tags origin "refs/tags/$TAG")" ]] || { echo "Tag already exists: $TAG" >&2; exit 1; }
gh auth status >/dev/null
bash "$ROOT/scripts/verify-native-release-assets.sh" "$ASSET_DIR" "$VERSION"
ASSET_DIR="$(cd -- "$ASSET_DIR" && pwd -P)"
ASSETS=(
  "$ASSET_DIR/spamgate-launcher-linux-amd64"
  "$ASSET_DIR/spamgate-worker-linux-amd64"
  "$ASSET_DIR/spamgate-linux-amd64"
  "$ASSET_DIR/spamgate-windows-amd64.exe"
  "$ASSET_DIR/SHA256SUMS.txt"
)
# gh release create atomically creates the lightweight tag at the requested commit.
# It refuses to overwrite an existing release; no --clobber is used.
gh release create "$TAG" "${ASSETS[@]}" \
  --repo "$REPO" --target "$EXPECTED_SHA" --title "SpamGate $TAG" \
  --generate-notes --prerelease
PUBLISHED="$(gh release view "$TAG" --repo "$REPO" --json assets --jq '.assets[].name' | sort)"
EXPECTED="$(printf '%s\n' SHA256SUMS.txt spamgate-launcher-linux-amd64 spamgate-worker-linux-amd64 spamgate-linux-amd64 spamgate-windows-amd64.exe | sort)"
[[ "$PUBLISHED" == "$EXPECTED" ]] || { echo 'ERROR: Published release asset inventory differs from the native contract' >&2; exit 1; }
TAG_SHA="$(git ls-remote --tags origin "refs/tags/$TAG" | awk '{print $1}')"
[[ "$TAG_SHA" == "$EXPECTED_SHA" ]] || { echo 'ERROR: Published tag does not point to the expected commit' >&2; exit 1; }
echo "Published verified native release $TAG at $EXPECTED_SHA; five required assets present."
echo 'The running mail server was not changed. Install using the existing Software Updates UI.'
