# Durable SMTP acceptance: relay-original preflight (2026-11-13)

## Change
The native SMTP listener now runs `validateRelayOriginal` on the exact bytes and envelope it will persist, immediately before `DeliveryQueue.Enqueue`. This is the same offline preflight that the worker's relay path runs before network access. The listener returns SMTP `554 5.6.0` for deterministically invalid originals and resets the transaction; it does not issue a durable `250` or enqueue them. Network failures and upstream capability mismatches are **not** classified as malformed originals and remain retryable after durable acceptance.

The preflight occurs **after** optional SpamGate tagging, so injected headers and altered wire framing are checked on the actual queued payload, not only on the incoming payload. The existing queue fsync boundary and post-queue audit semantics are unchanged. The listener does not modify the running Postfix/Dovecot configuration.

## Evidence and boundaries
- Source change: `internal/transport/smtp.go`.
- Regression matrix: `internal/transport/durable_acceptance_preflight_test.go` (ordinary and tagged originals, empty original, invalid envelope, malformed header, NUL and invalid UTF-8).
- The regression matrix exercises the shared preflight directly; it is **not** an end-to-end socket-to-queue acceptance test.
- Must verify exact-HEAD Go tests, isolated Postfix/Dovecot laboratory, crash recovery, disk-full behavior, SMTP response timing and production host acceptance separately.
- Existing architecture remains native Linux: `/opt/spamgate/spamgate`, `spamgate-worker`, `/opt/spamgate/data`, Milter ports 38470/38472.
- No long-term beta qualification is asserted; issues #1–#9 and real-host evidence remain open.
