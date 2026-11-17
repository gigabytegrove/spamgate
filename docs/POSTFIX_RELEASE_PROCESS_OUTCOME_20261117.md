# Postfix HOLD release process outcome contract — 2026-11-17

## Scope
The privileged native `spamgate-postfix-release` helper now returns process exit status **70** for `errReleaseOutcomeUnknown`. This includes subprocess failure, output-limit failure, interrupted execution after launch, and post-command reporting failure. It emits only the fixed stderr marker `SPAMGATE_RELEASE_OUTCOME_UNKNOWN` with a reconciliation instruction; no child stdout/stderr or envelope metadata is included. Status **64** means a refusal before the privileged action was attempted (invalid queue ID, missing root grant, canceled preflight, unavailable sink). Status **0** means the helper completed and reported success. This does not prove mailbox delivery.

## Critical operational limitation
The worker's parsing and persistence of exit status 70 has **not** been integrated or qualified in this pass. Operators and supervisors MUST NOT blindly retry exit status 70. Reconcile the original queue identity, recipient, timestamp, HOLD state and next-hop evidence in Postfix before deciding whether another action is safe. Queue IDs can be reused; a matching ID alone is insufficient.

## Evidence
Commits add the process contract and hermetic Go regression tests. No production Postfix/Dovecot host was accessed or changed. Local Go 1.23.2 cannot compile the repository's declared Go 1.27.4 module. CI must be inspected independently on the exact final HEAD. This is not issue #1 acceptance, nor beta qualification.

## Architecture
Preserves /opt/spamgate/spamgate as foreground launcher, spamgate-worker, /opt/spamgate/data persistent, Postfix Milter ports 38470/38472; no Docker runtime substitution or automatic mail-host configuration.
