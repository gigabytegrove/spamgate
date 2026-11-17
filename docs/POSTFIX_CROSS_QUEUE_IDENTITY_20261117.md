# Postfix cross-queue identity evidence — 2026-11-17

## Change
Native `postqueue -j` parsing now refuses any JSON queue entry without a nonempty queue name and valid queue ID, including active/deferred records. Previously these records were skipped and could conceal a queue ID collision with a HOLD entry. An incomplete snapshot cannot authorize privileged release or be displayed as correlated evidence.

## Regression contract
`TestParseValidatedPostfixHold` exercises valid mixed queues, missing/null/invalid non-HOLD IDs, missing non-HOLD queue name, duplicated IDs across queues, and multiple distinct queues. Invalid snapshots must return an error and no partial HOLD list.

## Scope and operational limitations
This is a fail-closed authorization boundary, not proof of queue identity against Postfix queue ID reuse over time. Native `/opt/spamgate/spamgate`, `spamgate-worker`, persistent `/opt/spamgate/data`, and Milter ports 38470/38472 remain unchanged. No mail-host configuration is modified. Live Postfix/Dovecot HOLD release, mailbox placement, ISPConfig persistence, and crash/recovery qualification are still required. GitHub CI and real-host evidence must be checked independently; this document does not certify beta readiness.
