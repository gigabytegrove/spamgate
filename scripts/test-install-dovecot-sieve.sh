#!/usr/bin/env bash
# Hermetic native Sieve installer test. No live Dovecot/Postfix changes.
set -Eeuo pipefail
base="$(mktemp -d /tmp/spamgate-sieve-test.XXXXXXXX)"
trap 'rm -rf -- "$base"' EXIT
mkdir -p "$base/bin" "$base/etc/conf.d"
cat > "$base/bin/doveconf" <<'MOCK'
#!/usr/bin/env bash
[[ "$*" == '-n' ]] || exit 88
[[ "${MOCK_DOVECOT_FAIL:-}" != 1 ]] || exit 77
if [[ "${MOCK_SIEVE_BEFORE:-}" == 1 ]]; then
  printf 'plugin { sieve_before = /etc/dovecot/sieve/existing.sieve }\n'
fi
MOCK
cat > "$base/bin/sievec" <<'MOCK'
#!/usr/bin/env bash
[[ "$#" == 3 && "$1" == -o ]] || exit 88
cp -- "$3" "$2"
MOCK
chmod 0755 "$base/bin/doveconf" "$base/bin/sievec"
export PATH="$base/bin:$PATH"
export SPAMGATE_SIEVE_TEST_MODE=1
export SPAMGATE_SIEVE_TEST_CONFIG_DIR="$base/etc"
script="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/install-dovecot-sieve.sh"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
"$script" --preview > "$base/preview.log"
[[ ! -e "$base/etc/sieve" ]] || fail 'Preview created a directory'
grep -q 'Read-only preview' "$base/preview.log" || fail 'Missing preview status'
if "$script" --apply > "$base/out" 2>&1; then fail 'Unconfirmed apply succeeded'; fi
[[ ! -e "$base/etc/sieve" ]] || fail 'Unconfirmed apply wrote files'
export MOCK_SIEVE_BEFORE=1
if "$script" --apply --confirm DOVECOT-SIEVE > "$base/out" 2>&1; then fail 'Existing Sieve rule was overridden'; fi
unset MOCK_SIEVE_BEFORE
[[ ! -e "$base/etc/sieve" ]] || fail 'Existing rule refusal wrote files'
cat > "$base/bin/doveconf" <<'MOCK'
#!/usr/bin/env bash
[[ "$*" == '-n' ]] || exit 88
if [[ -f "$SPAMGATE_SIEVE_TEST_CONFIG_DIR/conf.d/99-spamgate-junk.conf" ]]; then exit 77; fi
MOCK
chmod 0755 "$base/bin/doveconf"
if "$script" --apply --confirm DOVECOT-SIEVE > "$base/out" 2>&1; then fail 'Invalid config succeeded'; fi
for f in "$base/etc/sieve/spamgate-junk.sieve" "$base/etc/sieve/spamgate-junk.svbin" "$base/etc/conf.d/99-spamgate-junk.conf" "$base/etc/conf.d/99-spamgate-junk.sha256"; do
  [[ ! -e "$f" ]] || fail "Failed validation retained $f"
done
cat > "$base/bin/sievec" <<'MOCK'
#!/usr/bin/env bash
exit 71
MOCK
chmod 0755 "$base/bin/sievec"
if "$script" --apply --confirm DOVECOT-SIEVE > "$base/out" 2>&1; then fail 'Compiler failure succeeded'; fi
if [[ -d "$base/etc/sieve" ]] && [[ -n "$(find "$base/etc/sieve" -mindepth 1 -print -quit)" ]]; then fail 'Compiler failure retained staged artifacts'; fi
cat > "$base/bin/sievec" <<'MOCK'
#!/usr/bin/env bash
[[ "$#" == 3 && "$1" == -o ]] || exit 88
cp -- "$3" "$2"
MOCK
chmod 0755 "$base/bin/sievec"
cat > "$base/bin/doveconf" <<'MOCK'
#!/usr/bin/env bash
[[ "$*" == '-n' ]] || exit 88
MOCK
chmod 0755 "$base/bin/doveconf"
"$script" --apply --confirm DOVECOT-SIEVE > "$base/applied.log"
for f in "$base/etc/sieve/spamgate-junk.sieve" "$base/etc/sieve/spamgate-junk.svbin" "$base/etc/conf.d/99-spamgate-junk.conf" "$base/etc/conf.d/99-spamgate-junk.sha256"; do
  [[ -f "$f" && ! -L "$f" ]] || fail "Missing installed $f"
done
if "$script" --apply --confirm DOVECOT-SIEVE > "$base/out" 2>&1; then fail 'Existing install overwritten'; fi
printf '\n# local modification\n' >> "$base/etc/conf.d/99-spamgate-junk.conf"
if "$script" --remove --confirm REMOVE-DOVECOT-SIEVE > "$base/out" 2>&1; then fail 'Modified config was deleted'; fi
[[ -f "$base/etc/sieve/spamgate-junk.sieve" ]] || fail 'Removal partially changed files'
sed -i '$d' "$base/etc/conf.d/99-spamgate-junk.conf"
sed -i '$d' "$base/etc/conf.d/99-spamgate-junk.conf"
if "$script" --remove > "$base/out" 2>&1; then fail 'Unconfirmed removal succeeded'; fi
"$script" --remove --confirm REMOVE-DOVECOT-SIEVE > "$base/removed.log"
[[ ! -e "$base/etc/conf.d/99-spamgate-junk.conf" && ! -e "$base/etc/sieve/spamgate-junk.sieve" ]] || fail 'Removal left active configuration'
ln -s "$base/elsewhere" "$base/etc/sieve/spamgate-junk.sieve"
if "$script" --apply --confirm DOVECOT-SIEVE > "$base/out" 2>&1; then fail 'Symlinked destination accepted'; fi
[[ ! -e "$base/elsewhere" ]] || fail 'Symlink target was created'
printf 'PASS: read-only preview, confirmation, conflict refusal, validation rollback, install, drift-safe remove, symlink refusal\n'
