# Native SMTP relay endpoint boundary — 2026-11-22

## Scope
Production issue #3 (SMTP interoperability/security) and issue #2 (delivery retry boundary). The existing relay already checked TLS/authentication settings; this change additionally validates the relay destination at environment parsing and immediately before dialing. It rejects service-name/zero/out-of-range ports, invalid numeric IP literals, Unicode or malformed DNS labels, control characters, and IPv6 zone identifiers. It accepts explicit IPv4, bracketed IPv6, and ASCII DNS hostnames. It does not change the required TLS policy or the durable queue acceptance contract.

## Architecture invariants
Native foreground /opt/spamgate/spamgate, worker spamgate-worker, persistent /opt/spamgate/data, and Postfix Milter ports 38470/38472 remain unchanged. No mail-server settings, production services, Docker runtime, release artifacts, or GitHub Actions were changed.

## Qualification ledger
Source: three GitHub commits beginning at 43e96958738abd43d2b0637dfcffadf408451a94. Added unit regressions for valid and malformed endpoint forms. Full repository Go compilation, complete regression suite, isolated native Linux builder tests, real SMTP/TLS interoperability, and production mail-host testing: NOT EXECUTED. Do not treat source publication or committed tests as a passing qualification.

## Remaining gates
Issues #1–#9 remain open. Prioritize accepted-original crash/failure injection, Postfix hold/recipient correlation, Dovecot final mailbox placement, SMTP/authentication vectors, classifier precision/recall, tenant-policy conflicts, diagnostics, browser acceptance, and backup/restore/update/rollback. A valid configured relay endpoint alone does not establish downstream availability or delivery success.
