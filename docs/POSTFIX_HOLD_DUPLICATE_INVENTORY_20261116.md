# Postfix HOLD inventory integrity — 2026-11-16

## Change

The native Postfix queue inventory parser now rejects repeated HOLD queue identifiers instead of returning multiple records for the same identifier. Identical duplicate records are also rejected: neither the browser inventory nor the privileged release path should rely on selecting an arbitrary record. Queue IDs remain case-sensitive.

The existing parser continues to reject malformed or ambiguous JSON, incomplete ownership evidence, invalid identifiers, and inventories with more than 1000 held messages. Regression tests cover identical duplicate IDs, conflicting recipient records, distinct case-sensitive IDs, and the 1000/1001 capacity boundary.

## Qualification boundary

These tests exercise pure inventory parsing. They do not prove actual Postfix HOLD/release behavior, queue-ID reuse across time, real-host privileged helper installation, Dovecot delivery, ISPConfig persistence, or an end-to-end authenticated browser workflow. No running mail server was changed. The launcher remains /opt/spamgate/spamgate, worker spamgate-worker, persistent state /opt/spamgate/data, and Milter ports 38470/38472.

Before closing issue #9, obtain independent real mail-host evidence of correlated HOLD ownership, release, queue transitions, mailbox disposition and adversarial reused-ID cases. Issues #1–#9 remain open pending cumulative qualification.
