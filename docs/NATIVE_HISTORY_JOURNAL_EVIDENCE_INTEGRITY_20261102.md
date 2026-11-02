# Native history journal evidence integrity — 2026-11-02

## Scope

Production gates #2 and #6: durable delivery audit and actionable forensic diagnostics. The existing native launcher, worker, data directory, and Milter ports remain unchanged. No mail-server configuration or live message is modified.

## Failure mode and correction

Go's permissive JSON decoder accepts repeated object fields, case-insensitive aliases and malformed Unicode substitutions. Previously, startup and shared-history reconciliation could accept contradictory journal records. The read-only history auditor compared only the latest event's action and timestamp, allowing sender, recipient, delivery, findings or operator-attribution drift to be reported as consistent.

A common strict decoder now validates every event before startup loading, cross-process reconciliation and read-only auditing. It rejects duplicate and Unicode-aliased keys, malformed Unicode, trailing values and missing scan IDs. Unknown non-conflicting fields remain readable for forward compatibility. Audit comparison now covers the full persisted event representation rather than just action and timestamp; transient header snapshots remain excluded.

## Operational behavior

- An ambiguous journal fails startup or reconciliation rather than silently selecting a contradictory verdict.
- Reconciliation refusal does not append a new event or alter the existing journal.
- The auditor reports `corrupt` for invalid event encoding and `mismatch` for valid but altered retained events, without including private addresses or message contents.
- The journal is not automatically rewritten, truncated, repaired or replayed.
- SHA-256 and full-event comparisons are integrity checks against accidental or unauthorized changes detectable relative to the in-memory snapshot, **not** authenticated signatures or proof against an attacker who can rewrite both disk and memory.
- A historical journal that contains formerly tolerated ambiguous JSON requires operator investigation and an evidence-preserving recovery plan; do not auto-normalize it.

## Verification and outstanding gates

Regression coverage includes startup refusal, append reconciliation refusal, read-only tamper detection, private-data redaction and compatible unknown fields. Independent power-loss/disk-full fault injection, production ISPConfig/Postfix/Dovecot qualification, representative classifier false-positive measurement, tenant policies, browser acceptance and native disaster recovery remain open. Do not declare the October 31 long-term beta deadline met without full end-to-end evidence.
