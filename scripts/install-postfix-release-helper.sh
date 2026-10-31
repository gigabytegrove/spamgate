#!/usr/bin/env bash
# Explicit, opt-in installation of the narrow privileged Postfix HOLD helper.
# Never touches Postfix configuration, service state, or any held message.
set -Eeuo pipefail
umask 077

usage() {
  cat <<'TEXT'
Usage: install-postfix-release-helper.sh [--preview]
       sudo install-postfix-release-helper.sh --apply --confirm POSTFIX-HOLD-RELEASE

Preview is read-only. Apply installs a root-owned, non-setuid helper at
/usr/local/libexec/spamgate/postfix-hold-release and a restricted sudoers
entry for the dedicated spamgate account. The compiled binary
'spamgate-postfix-release' must be beside this script. Nothing changes
Postfix configuration or restarts the mail server. Back up existing local
privilege policy before applying; existing entries are never overwritten.
TEXT
}

mode=preview
confirm=''
while (($#)); do
  case "$1" in
    --preview) mode=preview; shift ;;
    --apply) mode=apply; shift ;;
    --confirm) (($# >= 2)) || { echo 'Missing confirmation' >&2; exit 2; }; confirm="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unsupported option: $1" >&2; exit 2 ;;
  esac
done

helper='/usr/local/libexec/spamgate/postfix-hold-release'
sudoers='/etc/sudoers.d/spamgate-postfix-release'
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source_binary="$script_dir/spamgate-postfix-release"
if [[ "$mode" == preview ]]; then
  printf 'Would install root-owned helper: %s\n' "$helper"
  printf 'Would install sudoers entry: %s\n' "$sudoers"
  printf 'Required source binary: %s\n' "$source_binary"
  printf 'Would permit spamgate to invoke only the validated Postfix HOLD release helper.\n'
  printf 'No files or mail services changed.\n'
  exit 0
fi

[[ "$confirm" == POSTFIX-HOLD-RELEASE ]] || { echo 'Exact confirmation required' >&2; exit 2; }
[[ "$EUID" -eq 0 ]] || { echo 'Apply requires root' >&2; exit 2; }
command -v visudo >/dev/null || { echo 'visudo required' >&2; exit 2; }
id spamgate >/dev/null 2>&1 || { echo 'Dedicated spamgate user missing' >&2; exit 2; }
[[ -x /usr/sbin/postsuper ]] || { echo 'Postfix postsuper missing' >&2; exit 2; }
[[ -x /usr/bin/sudo ]] || { echo 'sudo executable missing' >&2; exit 2; }
[[ -f "$source_binary" && ! -L "$source_binary" && -x "$source_binary" ]] || { echo 'Compiled Linux helper missing or unsafe' >&2; exit 2; }
[[ ! -e "$helper" && ! -L "$helper" && ! -e "$sudoers" && ! -L "$sudoers" ]] || { echo 'Existing helper or privilege policy: refusing overwrite' >&2; exit 2; }
[[ -d /etc/sudoers.d && ! -L /etc/sudoers.d ]] || { echo 'Unsafe sudoers directory' >&2; exit 2; }
install -d -m 0755 -o root -g root /usr/local/libexec/spamgate
stage_helper="$(mktemp /usr/local/libexec/spamgate/.postfix-hold-release.XXXXXXXX)"
stage_policy="$(mktemp /etc/sudoers.d/.spamgate-postfix-release.XXXXXXXX)"
cleanup() { rm -f -- "$stage_helper" "$stage_policy"; }
trap cleanup EXIT
install -m 0755 -o root -g root "$source_binary" "$stage_helper"
cat > "$stage_policy" <<'POLICY'
Defaults:spamgate env_reset, !setenv
spamgate ALL=(root) NOPASSWD: /usr/local/libexec/spamgate/postfix-hold-release *
POLICY
chown root:root "$stage_policy"
chmod 0440 "$stage_policy"
visudo -cf "$stage_policy" >/dev/null
# No mail server mutation; publication only after validating the exact policy.
[[ ! -e "$helper" && ! -e "$sudoers" ]] || { echo 'Concurrent privilege installation detected' >&2; exit 2; }
mv -T -- "$stage_helper" "$helper"
mv -T -- "$stage_policy" "$sudoers"
printf 'Installed narrow Postfix release privilege boundary. No mail services changed.\n'
printf 'To uninstall: sudo rm -- %q %q\n' "$helper" "$sudoers"
