# Native SMTP command idle timeout — 2026-11-22

## Scope
The native SMTP listener now limits each idle command read to 30 seconds while preserving its existing four-minute absolute session deadline. A timeout returns SMTP 421 (best effort), malformed command framing retains SMTP 500, and a clean EOF does not provoke an additional SMTP reply. DATA reads retain the absolute session budget, not the shorter command idle limit, so a valid large message is not cut off after 30 seconds of DATA transmission.

## Production gates
Issue #2 (SMTP interoperability), issue #6 (actionable diagnostics), and issue #1 (availability of the Postfix content-filter handoff) are affected. This change does not establish Postfix/Dovecot compatibility, queue crash safety, classifier accuracy, tenant policies, UI completeness, backup/restore, or update/rollback qualification. All nine production issues remain open.

## Qualification
Source changes and deterministic tests were committed via the GitHub source-control connector. No GitHub Actions were invoked. Owner-controlled native Linux compilation, complete regressions, Postfix/Dovecot live testing, and mail-host acceptance were NOT EXECUTED. No production host, mail server, systemd unit, or deployment was changed. The missed 2026-10-31 beta target remains missed.
