#!/usr/bin/env bash
# Optional native Dovecot LDA Sieve attachment. No mail service reloads.
set -Eeuo pipefail
umask 077
usage() {
  cat <<'HELP'
Usage: install-dovecot-sieve.sh [--preview]
       install-dovecot-sieve.sh --apply --confirm DOVECOT-SIEVE
       install-dovecot-sieve.sh --remove --confirm REMOVE-DOVECOT-SIEVE
Read-only by default. Explicit apply adds a dedicated Sieve-before rule for
Dovecot LDA only. It does not restart Dovecot, change Postfix, create mailboxes,
or alter existing Sieve rules. Remove refuses locally edited files. Review
mailbox and LDA/LMTP topology before opting in; restart Dovecot yourself after
successful configuration validation and live mail-flow planning.
HELP
}
die() { printf 'STOP: %s\n' "$*" >&2; exit 2; }
mode=preview
confirm=''
while (($#)); do
  case "$1" in
    --preview) mode=preview; shift ;;
    --apply) mode=apply; shift ;;
    --remove) mode=remove; shift ;;
    --confirm) (($# >= 2)) || die 'Missing confirmation value'; confirm="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
source_rule="$script_dir/fixtures/spamgate-junk.sieve"
[[ -f "$source_rule" && ! -L "$source_rule" ]] || die "Missing trusted rule: $source_rule"
# Hermetic tests use a private /tmp directory, never the real Dovecot tree.
confdir=/etc/dovecot
if [[ "${SPAMGATE_SIEVE_TEST_MODE:-}" == 1 ]]; then
  confdir="${SPAMGATE_SIEVE_TEST_CONFIG_DIR:-}"
  [[ "$confdir" == /tmp/* && "$confdir" != *'/../'* && "$confdir" != *'/./'* ]] || die 'Invalid isolated test directory'
fi
[[ -d "$confdir" && ! -L "$confdir" ]] || die "Dovecot configuration directory unavailable or unsafe: $confdir"
rule="$confdir/sieve/spamgate-junk.sieve"
compiled="$confdir/sieve/spamgate-junk.svbin"
snippet="$confdir/conf.d/99-spamgate-junk.conf"
manifest="$confdir/conf.d/99-spamgate-junk.sha256"
for parent in "$confdir/sieve" "$confdir/conf.d"; do
  if [[ -e "$parent" || -L "$parent" ]]; then
    [[ -d "$parent" && ! -L "$parent" ]] || die "Unsafe configuration directory: $parent"
  fi
done
for target in "$rule" "$compiled" "$snippet" "$manifest"; do
  [[ ! -L "$target" ]] || die "Refusing symlinked configuration: $target"
done
snippet_content() {
  cat <<'CONF'
# SpamGate opt-in: only Dovecot LDA delivery, not LMTP or IMAP.
# Existing Sieve rules must be reviewed before enabling this integration.
protocol lda {
  mail_plugins = $mail_plugins sieve
}
plugin {
  sieve_before = /etc/dovecot/sieve/spamgate-junk.sieve
}
CONF
}
if [[ "$mode" == preview ]]; then
  printf 'Dovecot directory: %s\n' "$confdir"
  printf 'Rule: %s\nCompiled: %s\nSnippet: %s\nManifest: %s\n' "$rule" "$compiled" "$snippet" "$manifest"
  for target in "$rule" "$compiled" "$snippet" "$manifest"; do
    if [[ -e "$target" ]]; then printf 'EXISTS: %s\n' "$target"; else printf 'ABSENT: %s\n' "$target"; fi
  done
  printf 'Read-only preview; no files, services or mailboxes changed.\n'
  exit 0
fi
if [[ "${SPAMGATE_SIEVE_TEST_MODE:-}" != 1 ]]; then
  [[ "$EUID" -eq 0 ]] || die 'Root required for changes'
  if [[ -d /usr/local/ispconfig/server || -d /usr/local/ispconfig/interface || -d /var/cpanel || -d /usr/local/psa || -d /usr/local/directadmin ]]; then
    die 'Hosting panel detected; use its supported Dovecot configuration workflow'
  fi
fi
command -v sha256sum >/dev/null || die 'sha256sum required'
if [[ "$mode" == remove ]]; then
  [[ "$confirm" == REMOVE-DOVECOT-SIEVE ]] || die 'Explicit --confirm REMOVE-DOVECOT-SIEVE required'
  for target in "$rule" "$compiled" "$snippet" "$manifest"; do
    [[ -f "$target" && ! -L "$target" ]] || die "Cannot safely remove missing/unsafe file: $target"
  done
  cmp -s -- "$source_rule" "$rule" || die 'Installed Sieve rule has changed; manual review required'
  cmp -s -- "$snippet" <(snippet_content) || die 'Installed Dovecot snippet has changed; manual review required'
  (cd "$confdir" && sha256sum --status -c "${manifest#"$confdir"/}") || die 'Manifest integrity failed; no files removed'
  expected_names="$(printf '%s\n' "$rule" "$compiled" "$snippet" | LC_ALL=C sort)"
  actual_names="$(sed -nE 's/^[[:xdigit:]]{64} [ *](.*)$/\1/p' "$manifest" | LC_ALL=C sort)"
  [[ "$actual_names" == "$expected_names" ]] || die 'Unexpected manifest entries; no files removed'
  rm -- "$manifest" "$snippet" "$compiled" "$rule"
  printf 'SpamGate Dovecot Sieve files removed. Restart Dovecot manually after validation.\n'
  exit 0
fi
[[ "$confirm" == DOVECOT-SIEVE ]] || die 'Explicit --confirm DOVECOT-SIEVE required'
command -v sievec >/dev/null || die 'Dovecot sievec compiler required'
command -v doveconf >/dev/null || die 'Dovecot doveconf required'
[[ -d "$confdir/conf.d" ]] || die 'Dovecot conf.d directory missing'
for target in "$rule" "$compiled" "$snippet" "$manifest"; do
  [[ ! -e "$target" ]] || die "Existing configuration will not be overwritten: $target"
done
active="$(doveconf -n)" || die 'Cannot inspect current Dovecot configuration'
if grep -Eq '(^|[[:space:]])sieve_before[[:space:]]*=' <<< "$active"; then
  die 'Existing sieve_before configuration detected; manual integration required'
fi
created=()
stage=''
rollback() {
  if [[ -n "$stage" && -d "$stage" && ! -L "$stage" ]]; then rm -rf -- "$stage" || true; fi
  local target
  for target in "${created[@]}"; do
    [[ "$target" == "$stage" ]] && continue
    if [[ -d "$target" && ! -L "$target" ]]; then rmdir -- "$target" 2>/dev/null || true;
    else rm -f -- "$target" 2>/dev/null || true; fi
  done
}
committed=false
cleanup() { if [[ "$committed" != true ]]; then rollback; fi; }
trap cleanup EXIT
if [[ ! -d "$confdir/sieve" ]]; then
  install -d -m 0755 "$confdir/sieve"
  created+=("$confdir/sieve")
fi
stage="$(mktemp -d "$confdir/sieve/.spamgate-stage.XXXXXXXX")"
created=("$stage" "${created[@]}")
install -m 0644 -- "$source_rule" "$stage/spamgate-junk.sieve"
sievec "$stage/spamgate-junk.sieve"
snippet_content > "$stage/99-spamgate-junk.conf"
chmod 0644 "$stage/99-spamgate-junk.conf" "$stage/spamgate-junk.svbin"
install -m 0644 -- "$stage/spamgate-junk.sieve" "$rule"; created=("$rule" "${created[@]}")
install -m 0644 -- "$stage/spamgate-junk.svbin" "$compiled"; created=("$compiled" "${created[@]}")
install -m 0644 -- "$stage/99-spamgate-junk.conf" "$snippet"; created=("$snippet" "${created[@]}")
sha256sum "$rule" "$compiled" "$snippet" > "$manifest"; chmod 0600 "$manifest"; created=("$manifest" "${created[@]}")
doveconf -n >/dev/null || die 'Dovecot validation failed'
rm -rf -- "$stage"
committed=true
trap - EXIT
printf 'Sieve integration installed and doveconf validated. Dovecot was NOT restarted.\n'
printf 'Verify LDA, mailbox existence, and mail flow before manually restarting Dovecot.\n'
