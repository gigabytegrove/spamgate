#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/install" "$TMP/assets" "$TMP/bad-install"
cat > "$TMP/install/spamgate" <<'EOS'
#!/bin/sh
[ "$1" = -version ] && { echo 0.6.0-alpha.15; exit 0; }
exit 4
EOS
cat > "$TMP/assets/spamgate-launcher-linux-amd64" <<'EOS'
#!/bin/sh
[ "$1" = -version ] && { echo 0.6.0-alpha.16; exit 0; }
exec "$(dirname "$0")/spamgate-worker" "$@"
EOS
cat > "$TMP/assets/spamgate-worker-linux-amd64" <<'EOS'
#!/bin/sh
[ "$1" = -version ] && { echo 0.6.0-alpha.16; exit 0; }
exit 0
EOS
chmod 755 "$TMP/install/spamgate" "$TMP/assets"/*
(cd "$TMP/assets" && sha256sum spamgate-launcher-linux-amd64 spamgate-worker-linux-amd64 > SHA256SUMS.txt)
# Refuse corrupted downloaded assets without modifying the old worker.
cp -a "$TMP/install/spamgate" "$TMP/bad-install/spamgate"
printf '\ncorruption' >> "$TMP/assets/spamgate-worker-linux-amd64"
if bash "$ROOT/migrate-native-launcher.sh" "$TMP/bad-install" "$TMP/assets" >/dev/null 2>&1; then
 echo 'Corrupt asset was accepted' >&2;exit 1
fi
test "$("$TMP/bad-install/spamgate" -version)" = '0.6.0-alpha.15'
test ! -e "$TMP/bad-install/spamgate-worker"
# Verify the safe, successful, one-time transition.
sed -i '$d' "$TMP/assets/spamgate-worker-linux-amd64"
(cd "$TMP/assets" && sha256sum spamgate-launcher-linux-amd64 spamgate-worker-linux-amd64 > SHA256SUMS.txt)
bash "$ROOT/migrate-native-launcher.sh" "$TMP/install" "$TMP/assets" >/dev/null
test "$("$TMP/install/spamgate" -version)" = 0.6.0-alpha.16
test "$("$TMP/install/spamgate-worker" -version)" = 0.6.0-alpha.16
test "$("$TMP/install/spamgate.pre-native-split-0.6.0-alpha.15" -version)" = 0.6.0-alpha.15
if bash "$ROOT/migrate-native-launcher.sh" "$TMP/install" "$TMP/assets" >/dev/null 2>&1; then
 echo 'Second migration should refuse overwrite' >&2;exit 1
fi
# Refuse a process still executing the current executable, even if port 38470 is not used.
mkdir -p "$TMP/running-install"
cp /bin/sleep "$TMP/running-install/spamgate"
"$TMP/running-install/spamgate" 20 &
pid=$!
set +e
output="$(bash "$ROOT/migrate-native-launcher.sh" "$TMP/running-install" "$TMP/assets" 2>&1)"
rc=$?
set -e
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
if (( rc == 0 )) || [[ "$output" != *'process is running'* ]]; then
 echo "Running executable was not detected: $rc, $output" >&2; exit 1
fi
echo 'Native split migration: checksum refusal, preservation, install, repeat refusal PASS'