#!/usr/bin/env bash
set -Eeuo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
installer="$root/install-postfix-release-helper.sh"
preview="$(bash "$installer" --preview)"
[[ "$preview" == *'No files or mail services changed.'* ]]
[[ "$preview" == *'/usr/local/libexec/spamgate/postfix-hold-release'* ]]
[[ "$preview" == *'/etc/sudoers.d/spamgate-postfix-release'* ]]
if bash "$installer" --apply > /dev/null 2>&1; then
  echo 'Unsafe: installer accepted apply without confirmation' >&2
  exit 1
fi
if bash "$installer" --apply --confirm wrong > /dev/null 2>&1; then
  echo 'Unsafe: installer accepted incorrect confirmation' >&2
  exit 1
fi
if bash "$installer" --unsupported > /dev/null 2>&1; then
  echo 'Unsafe: installer accepted unknown option' >&2
  exit 1
fi
printf 'Read-only preview and unsafe apply refusals passed.\n'
