#!/usr/bin/env bash
# Native Postfix attachment; never changes an ISPConfig/cPanel/Plesk/DirectAdmin
# installation or removes an existing third-party Milter.
set -Eeuo pipefail

usage() {
  cat <<'TEXT'
Usage: configure-postfix.sh [--preview] [--apply --confirm POSTFIX-MILTER]
                            [--detach --confirm POSTFIX-MILTER]
                            [--allow-existing-milters]

Default is read-only preview. --apply requires root and a running local
SpamGate Milter on 127.0.0.1:38472. Only direct, unmanaged Postfix hosts can
be changed automatically. Existing Milter chains require explicit review.
Every mutation backs up main.cf, runs postfix check and reloads Postfix;
failed checks trigger an immediate restoration attempt.

On ISPConfig, cPanel, Plesk and DirectAdmin: use the hosting panel's supported
configuration workflow. SpamGate NEVER changes their MTA configuration.
TEXT
}

die() { printf 'STOP: %s\n' "$*" >&2; exit 2; }
mode=preview
confirm=''
allow_existing=false
while (( $# )); do
  case "$1" in
    --preview) mode=preview; shift ;;
    --apply) mode=apply; shift ;;
    --detach) mode=detach; shift ;;
    --confirm) (( $# >= 2 )) || die '--confirm requires a value'; confirm="$2"; shift 2 ;;
    --allow-existing-milters) allow_existing=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unrecognized parameter: $1" ;;
  esac
done

command -v postconf >/dev/null 2>&1 || die 'Postfix postconf not found. This utility supports Postfix only.'
command -v postfix >/dev/null 2>&1 || die 'Postfix executable not found.'
if [[ -e /usr/local/ispconfig/server || -e /usr/local/ispconfig/interface \
   || -d /var/cpanel || -e /usr/local/cpanel/cpanel \
   || -d /usr/local/psa || -d /usr/local/directadmin ]]; then
  die 'A hosting panel manages this server. No files changed. Use its managed MTA configuration workflow.'
fi

local_milter='inet:127.0.0.1:38472'
existing="$(postconf -h smtpd_milters)" || die 'Cannot read existing smtpd_milters.'
config_dir="$(postconf -h config_directory)" || die 'Cannot locate Postfix configuration directory.'
[[ -n "$config_dir" && "$config_dir" = /* ]] || die 'Invalid Postfix configuration directory.'
main_conf="${config_dir%/}/main.cf"
[[ -f "$main_conf" && ! -L "$main_conf" ]] || die "Expected regular Postfix configuration missing: $main_conf"

has_ours=false
IFS=', ' read -r -a current_parts <<< "$existing"
for part in "${current_parts[@]}"; do
  [[ "$part" == "$local_milter" ]] && has_ours=true
 done
next="$existing"
if [[ "$mode" == detach ]]; then
  if [[ "$has_ours" == false ]]; then
    printf 'SpamGate Milter is not attached; nothing to detach.\n'
    exit 0
  fi
  next=''
  # Convert whitespace-separated Postfix tokens into a canonical comma list.
  for part in "${current_parts[@]}"; do
    [[ -z "$part" || "$part" == "$local_milter" ]] && continue
    [[ -n "$next" ]] && next+=', '
    next+="$part"
  done
elif [[ "$has_ours" == false ]]; then
  if [[ -n "${existing//[[:space:]]/}" ]]; then next+=', '; fi
  next+="$local_milter"
fi

printf 'Current smtpd_milters: %s\n' "${existing:-<empty>}"
printf 'Proposed smtpd_milters: %s\n' "${next:-<empty>}"
printf 'No changes to non_smtpd_milters, other filters, ports 25/465/587, or the delivery queue.\n'
if [[ "$mode" == preview ]]; then
  printf 'Read-only preview. For unmanaged Postfix, use --apply --confirm POSTFIX-MILTER after reviewing mail-flow and testing.\n'
  exit 0
fi
[[ "$confirm" == 'POSTFIX-MILTER' ]] || die 'Explicit --confirm POSTFIX-MILTER required.'
[[ "$EUID" -eq 0 ]] || die 'Only root may change Postfix configuration.'
if [[ "$mode" == apply && "$has_ours" == false && "$allow_existing" == false && -n "${existing//[[:space:]]/}" ]]; then
  die 'Existing third-party milters detected. Inspect their order and use --allow-existing-milters only after checking compatibility.'
fi
if [[ "$mode" == apply ]]; then
  command -v timeout >/dev/null 2>&1 || die 'timeout utility required for Milter reachability check.'
  timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/38472' >/dev/null 2>&1 || die 'Local SpamGate Milter is not listening on 127.0.0.1:38472.'
fi
if [[ "$next" == "$existing" ]]; then
  printf 'Already configured; no changes performed.\n'
  exit 0
fi

# Do not blindly replace postconf-managed configuration on failed validation.
backup_root='/var/backups/spamgate/postfix'
install -d -m 0700 -o root -g root "$backup_root"
backup="$(mktemp "$backup_root/main.cf.XXXXXXXXXX")"
cp -p -- "$main_conf" "$backup"
chmod 0600 "$backup"
rollback_needed=true
rollback() {
  if [[ "$rollback_needed" == true ]]; then
    printf 'Postfix integration failed; restoring backup %s\n' "$backup" >&2
    cp -p -- "$backup" "$main_conf" || printf 'EMERGENCY: backup restoration failed. Restore %s manually.\n' "$backup" >&2
    postfix check || true
    postfix reload || true
  fi
}
trap rollback ERR
postconf -e "smtpd_milters = $next"
postfix check
postfix reload
rollback_needed=false
trap - ERR
printf 'Postfix updated successfully. Original main.cf backed up: %s\n' "$backup"
printf 'Rollback (review intervening changes first): sudo cp -p -- %q %q && sudo postfix check && sudo postfix reload\n' "$backup" "$main_conf"
