# Native Postfix HOLD release: least-privilege helper (2026-10-31)

Issues #9 and #1. This change **does not** attach SpamGate to Postfix, restart
the mail server, release any message, or install privilege grants automatically.

## Root cause and boundary

Previously an unprivileged SpamGate worker used `sudo -n
/usr/sbin/postsuper -H QUEUE_ID`. An administrator who configured a broad
sudoers grant to make this work could accidentally allow unrestricted
`postsuper` operations. The worker now invokes only:

`/usr/bin/sudo -n -- /usr/local/libexec/spamgate/postfix-hold-release QUEUE_ID`

The optional Linux helper is compiled from
`cmd/spamgate-postfix-release`. It must run as root, accepts **exactly one**
alphanumeric queue ID of at most 32 characters, explicitly rejects Postfix's
reserved `ALL` argument, uses the fixed `/usr/sbin/postsuper -H` vector,
has an eight-second command deadline, bounded output, and a minimal environment.
There is no shell, no arbitrary command path, no queue deletion and no option
to release all messages. Root-run SpamGate still invokes the fixed Postfix
command directly. All HTTP authorization, scan-to-queue correlation, complete
recipient matching, cross-process lock and durable pre-command audit remain
mandatory.

## Optional host installation (manual, not automatic)

Build on a trusted Linux host with the project's qualified Go toolchain:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o scripts/spamgate-postfix-release ./cmd/spamgate-postfix-release
bash scripts/install-postfix-release-helper.sh --preview
sudo bash scripts/install-postfix-release-helper.sh --apply --confirm POSTFIX-HOLD-RELEASE
```

The installer requires the dedicated `spamgate` account, `visudo`, `sudo`,
and `/usr/sbin/postsuper`. It publishes a root-owned executable and a
validated `/etc/sudoers.d/spamgate-postfix-release` policy. It refuses
existing destinations instead of overwriting local privilege policy.
The policy permits that one helper command, with arbitrary *arguments* at
sudoers level; the helper itself strictly rejects all but one valid ID.
The helper is not setuid. The worker's opt-in environment variables
`SPAMGATE_POSTFIX_HOLD_ACTIONS=true` and
`SPAMGATE_POSTFIX_HOLD_INVENTORY=true` remain required.

To revoke the grant without touching Postfix, an administrator may remove
`/etc/sudoers.d/spamgate-postfix-release`; remove the installed helper
after the worker is no longer using it. No production deployment is performed
by this commit.

## Verification and remaining acceptance gates

Unit tests verify argument injection refusal, reserved `ALL`, non-root
refusal, fixed executable/argv, deadlines, propagated errors, bounded output,
and the worker's root/non-root command selection. The opt-in installer has
read-only preview and incorrect-confirmation refusal tests. The engineering
workflow compiles the native helper and includes it in its unreleased
checksummed artifact. The existing isolated Postfix/Dovecot CI covers the
mail path, but **does not yet exercise this sudoers helper as the real
unprivileged service account**.

A compromised worker permitted to call this helper can still release any
single valid queue ID; the helper is a command/argument boundary, not a
cryptographic queue ownership proof. Postfix queue ID reuse, external queue
mutation, local sudoers conflicts, real-host installation and rollback,
Sieve mailbox placement, and independent end-to-end evidence remain open.
Do not claim production readiness from passing unit tests or isolated CI.
