# Native spool lifecycle and collision evidence — 2026-11-01

Scope: read-only forensic qualification for the persistent native SMTP outbox at `/opt/spamgate/data/delivery-queue`. This is engineering progress for issues #2 and #6, **not** production beta acceptance.

## New evidence

`spamgate-spool-audit` reports `lifecycle_anomalies` in JSON and text, and exits 1 for suspicious state. It detects missing required timestamps, attempts exceeding the 16-attempt ceiling, an alleged delivered record without a relay attempt or receipt time, dead/in-flight records without an attempt, a receipt on an undelivered record, and scan evidence whose ID/sender/recipient set disagrees with the durable envelope. These are findings, **not automatic repairs**. Legacy records with no scan remain permitted.

Pending collision accounting now tracks every distinct immutable original per queue ID, not just the first one. For three pending files A, B, B sharing one ID, it reports one collision and one duplicate rather than two collisions. `pending_duplicate_ids` retains its previous meaning: additional files after the first for a given ID. `pending_conflicting_ids` counts newly encountered distinct originals after the first.

## Safety and interpretation

Run the native audit binary with `-dir /opt/spamgate/data/delivery-queue -json` as a read-only operator diagnostic. Findings contain quoted filenames and fixed descriptions, not sender, recipient, message body, subject or scan contents. Audit does not rename, delete, replay, repair, or acknowledge any SMTP original. Concurrent writes can produce a non-transactional observation; repeat under an offline maintenance window before a recovery decision. Existing checksum validation remains mandatory.

These heuristics do not prove SMTP delivery, exactly-once semantics, Postfix queue state, or Dovecot mailbox placement. They cannot establish historical receipt for a delivered spool record. A wall-clock rollback alone is not treated as a corruption finding. The source and tests must pass exact-commit CI; disposable-host and production-host qualification remain separate gates.

## Locked deployment

No changes to `/opt/spamgate/spamgate`, `spamgate-worker`, persistent data layout, or Milter ports 38470/38472. No Docker substitution and no running mail-server configuration changes.
