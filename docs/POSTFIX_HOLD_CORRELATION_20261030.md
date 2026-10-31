# Postfix HOLD correlation and complete recipient ownership — 2026-10-30

## Defect and scope

The read-only hold inventory previously attached a SpamGate scan ID using the
Postfix queue ID alone. Postfix can reuse queue IDs; the displayed scan could
therefore belong to another held message. The administrative release path also
accepted a *subset* of the scanned recipients, even though a multi-recipient
SMTP transaction must be treated as one envelope.

## Changes

The inventory now labels a held item with a scan ID only when exactly one
candidate scan and one held queue record exist, and the connector, HOLD action,
queue ID, sender, arrival timestamp (within 15 minutes), and complete recipient
multiset match. Ambiguous and truncated inventories remain visible but
uncorrelated. Release requires the same exact envelope correlation before
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
locking, complete history beyond the UI's bounded scan listing, independent
queue identity, and real Postfix/Dovecot mailbox evidence remain outstanding
under issues #1 and #9. Fail closed when identity is ambiguous. No service
configuration, Milter ports, data layout, or default Postfix failure action
changes in this patch.
