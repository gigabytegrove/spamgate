#!/usr/bin/env bash
# Hermetic preview-path regression test: never touches a real MTA.
set -Eeuo pipefail
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/bin" "$root/config"
printf 'smtpd_milters = inet:127.0.0.1:11332\n' > "$root/config/main.cf"
cat > "$root/bin/postconf" <<'MOCK'
#!/usr/bin/env bash
case "$*" in
  '-h smtpd_milters') echo 'inet:127.0.0.1:11332' ;;
  '-h config_directory') printf '%s\n' "$MOCK_POSTFIX_DIR" ;;
  *) echo 'unexpected postconf write in preview' >&2; exit 99 ;;
esac
MOCK
cat > "$root/bin/postfix" <<'MOCK'
#!/usr/bin/env bash
printf 'unexpected postfix invocation in preview: %s\n' "$*" >&2
exit 99
MOCK
chmod +x "$root/bin/postconf" "$root/bin/postfix"
export MOCK_POSTFIX_DIR="$root/config"
old_path="$PATH"
export PATH="$root/bin:$old_path"
original="$(sha256sum "$root/config/main.cf")"
output="$("$(dirname "$0")/configure-postfix.sh" --preview)"
[[ "$output" == *'inet:127.0.0.1:11332, inet:127.0.0.1:38472'* ]] || { echo 'Missing existing-milter preservation in preview' >&2; exit 1; }
[[ "$(sha256sum "$root/config/main.cf")" == "$original" ]] || { echo 'Preview modified Postfix configuration' >&2; exit 1; }
if "$(dirname "$0")/configure-postfix.sh" --apply >"$root/out" 2>"$root/err"; then
  echo 'Mutating mode succeeded without explicit confirmation' >&2
  exit 1
fi
[[ "$(sha256sum "$root/config/main.cf")" == "$original" ]] || { echo 'Unconfirmed apply modified Postfix config' >&2; exit 1; }
echo 'PASS: existing milters preserved; preview read-only; unconfirmed apply refused'
