# SpamGate alpha.11 — Postfix mail investigations and controlled hold actions

This release adds operational tools to bridge the gap between a SpamGate scan and actual Postfix evidence. It does not imply final mailbox delivery or unconditional Rspamd parity.

## Message investigation

An administrator can request `GET /api/v1/messages/{id}/investigation` in the authenticated message inspector. The response includes the original scan, recorded score/verdict, the Milter action requested, inbound header snapshot availability, exact Postfix queue-ID correlation to recent configured local logs, current read-only hold inventory, human review actions, and explicit unknown/failed evidence. Log matching is bounded to 4 MiB / 100 events; queue inventory is bounded to 5 MiB / 1000 entries. This is an evidence timeline, not a fabricated delivery receipt.

Required opt-in for hold inventory: `SPAMGATE_POSTFIX_HOLD_INVENTORY=true`; the same process must have access to `/usr/sbin/postqueue -j` on the *actual Postfix host*. Configure `SPAMGATE_POSTFIX_LOG_PATH=/var/log/mail.log` only when that regular file is locally readable. Containerized or remote SpamGate instances have no implicit Postfix host access.

## Releasing a Postfix hold

The new administrator-only `POST /api/v1/messages/{id}/postfix-release` endpoint is **disabled by default**. Explicitly set `SPAMGATE_POSTFIX_HOLD_ACTIONS=true` *and* enable hold inventory. The request must carry the exact Postfix queue ID, the confirmation text `release Postfix hold <ID>`, and a 12–512-character reason. Admin session, CSRF token, recorded Milter `postfix_hold_requested` verdict, exact queue ID, close arrival timestamp, matching envelope sender and corresponding recipients, and real current `postqueue -j` hold inventory must all be verified. A queue ID alone is insufficient.

Only `postsuper -H <ID>` is invoked; no arbitrary shell commands, queue deletion, wildcard IDs, or user-supplied executable paths. SpamGate persists `release_attempted` in its decision journal before execution to prevent unaudited or duplicate submissions. A successful command is marked `release_submitted`, **not** delivered. Failed or interrupted attempts intentionally remain blocked from blind retries; inspect the actual Postfix queue state and logs before further intervention. The UI never considers a Postfix hold equivalent to a SpamGate SMTP-quarantined original.

When running as root on the mail host, SpamGate uses `/usr/sbin/postsuper -H <ID>`. For the native unprivileged `spamgate` user, do not grant unrestricted sudo; a site administrator must deliberately provision an audited, restricted privilege path for precisely that command. Without it the action fails closed. Do not enable this feature on an arbitrary Internet-accessible installation or on a host whose queue ownership is not verified.

## Relay diagnostics

`GET /api/v1/integrations/diagnostics` now tests TCP reachability, SMTP greeting/EHLO, STARTTLS advertisement and verified TLS negotiation when required/implicit, plus advertised AUTH. It does not issue AUTH, MAIL FROM, RCPT TO or DATA and cannot certify mailbox delivery or credentials. TLS hostname/certificate validation is mandatory when TLS mode requires encryption; it never ignores invalid certificates. A missing or broken dependency is reported as the specific failing stage.

## Qualification still required

Live Postfix + Dovecot test transactions, policy stress tests, crash and rollback tests, external RFC authentication vectors, safe enterprise signing, and accurate mailbox-delivery reconciliation remain distinct release gates. Never describe an administrative release command as successful downstream delivery without independently observed recipient-side evidence.
