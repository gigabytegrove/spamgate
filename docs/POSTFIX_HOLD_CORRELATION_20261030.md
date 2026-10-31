# Postfix HOLD correlation and complete recipient ownership — 2026-10-30

## Defect and scope

The read-only hold inventory previously attached a SpamGate scan ID using the
Postfix queue ID alone. Postfix can reuse queue IDs; the displayed scan could
therefore belong to another held message. The administrative release path also
accepted a *subset* of the scanned recipients, even though a multi-recipient
SMTP transaction must be treated as one envelope.

## Changes

The inventory searches the complete retained scan history (not just the 1000-row UI history window) and now labels a held item with a scan ID only when exactly one
candidate scan and one held queue record exist, and the connector, HOLD action,
queue ID, sender, arrival timestamp (within 15 minutes), and complete recipient
multiset match. Ambiguous and truncated inventories remain visible but
uncorrelated. Release also rejects queue IDs appearing in more than one retained HOLD scan, and requires the same exact envelope correlation before
persisting an attempt and invoking the fixed Postfix command. Case-insensitive
address matching and the SMTP null reverse path remain supported.

No Postfix queue is modified by the inventory endpoint. A successful
`postsuper -H` still means *release submitted*, not mailbox delivery.

## Qualification and limitations

Automated tests cover partial, extra, duplicated and unrelated recipients;
truncated inventory; queue-ID reuse; duplicate held records; sender mismatch;
and the HTTP inventory and release routes. These are regression tests, not
production-host acceptance.

Postfix inventory is a point-in-time snapshot; a queue can change between
inventory and `postsuper -H`. The narrow privileged helper, cross-process
locking, independent
queue identity, and real Postfix/Dovecot mailbox evidence remain outstanding
under issues #1 and #9. Fail closed when identity is ambiguous. No service
configuration, Milter ports, data layout, or default Postfix failure action
changes in this patch.

## Regression found during CI

The first qualification run identified a cached inventory-slice mutation: an
annotated scan ID remained on the provider's backing slice even after the held
recipient set changed. The handler now copies the inventory and clears all
incoming annotations before independent correlation. An existing authorization
test fixture also lacked the new mandatory recipient count; it now models the
actual `postqueue -j` parser output. The failing run must not be considered
qualified; only a later exact-commit successful run establishes regression
status.

## Investigation timeline

The message investigation endpoint previously marked a HOLD as confirmed when
any queue entry shared its Postfix queue ID. It now uses the same complete
correlation and uniqueness checks as inventory and release. An uncorrelated
queue-ID hit is reported as unknown, not as an attributed hold or final mailbox
receipt. Regression tests cover sender mismatch, valid match, and reused IDs.
