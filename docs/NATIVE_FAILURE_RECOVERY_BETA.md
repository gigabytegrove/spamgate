# Native worker recovery and failure visibility (October 30, 2026)

## Preserved operator contract

- The foreground process remains `/opt/spamgate/spamgate`.
- Its child remains `/opt/spamgate/spamgate-worker`.
- Persistent data remains `/opt/spamgate/data`.
- The management listener remains port 38470; the configured Postfix Milter remains port 38472.
- The launcher does **not** edit Postfix, change `milter_default_action`, start a Docker container, or alter the live host.

## Implemented recovery

Previously, the launcher terminated after three worker crashes, after one failed startup, or after a failed crash-recovery startup. The new launcher continues attempting recovery while its foreground process is alive. Recovery delays grow from 2 seconds to a maximum of 30 seconds, preventing an uncontrolled fork storm. A clean child exit still ends the foreground session, and an exit code of 75 still selects the existing supervised update transaction.

After a healthy startup, the launcher probes `/healthz` every 15 seconds with a two-second request deadline and validates the expected worker version. Three consecutive failures cause a graceful child shutdown (up to seven seconds, then kill) and recovery. This detects web-handler hangs and version drift; **HTTP health is not a complete Milter protocol probe or proof of actual mail disposition**. Successful probes clear the consecutive-failure count. Five minutes of worker uptime resets the crash backoff history.

The foreground launcher itself still requires a parent process or operator to remain alive. If the launcher process or host dies, no in-process recovery can occur. An external init/service supervisor is a separate deployment decision, not introduced by this change.

## Postfix default action

The operator's `milter_default_action = accept` remains unchanged. If SpamGate is completely unavailable, Postfix can accept mail without inspection. Automatic worker restart reduces the window, but cannot eliminate this fundamental fail-open behavior. No implementation should label mail received during an unavailable Milter as scanned or protected.

## Diagnostic checks after a test-only deployment

Use read-only commands; do not intentionally crash the production worker while customer mail is flowing.

```bash
ps -eo pid,ppid,etime,args | grep '[s]pamgate'
ss -lntp | grep -E '38470|38472'
postconf -n | grep -E 'milter_default_action|smtpd_milters|non_smtpd_milters'
journalctl --since '2 hours ago' --no-pager | grep -Ei 'SpamGate launcher|milter|postfix' | tail -100
```

A crash-recovery acceptance test must be run on an isolated Postfix/Dovecot lab, with a deliberate worker crash, a new worker PID, recovered listeners, and a subsequent real Milter transaction. GitHub CI alone cannot establish a production mail-host result.

## Regression coverage

- Bounded exponential retry delay and immediate cancellation.
- Health success, wrong version, invalid JSON, and HTTP 503.
- Child crash exit code 2, followed by automatic restart without terminating the launcher.
- Initially broken child binary, repaired at the same path, followed by automatic recovery.
- Existing native staged update, rollback, lock, and migration tests remain mandatory.

## Outstanding gates

This change does not certify classifier detection accuracy, zero-score findings, Dovecot Junk placement, Postfix hold confirmation, SMTP authentication compliance, tenant policies, UI completeness, cold backup/restore, update rollback under disk failures, or real mail-host qualification. Those remain open and must be evaluated separately before long-term beta sign-off.
