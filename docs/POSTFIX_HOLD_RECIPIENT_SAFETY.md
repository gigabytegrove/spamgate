# Postfix hold release: complete recipient ownership evidence

The Postfix hold inventory reports both `recipient_count` and
`recipients_truncated`. The API intentionally shows at most 50 addresses per
held item, but **a truncated list is no longer treated as complete evidence**
when authorizing an irreversible `postsuper -H` operation.

Release fails closed when the inventory is truncated, the reported count
disagrees with visible recipients, the queue ID is malformed, or multiple
held entries share the same queue ID. Ambiguous queue IDs with multiple
historical scans no longer display an arbitrary correlated scan ID.

The operator still needs the exact queue ID, matching envelope sender,
recipient ownership, arrival-time correlation, CSRF token, administrator
privilege, explicit confirmation and a durable pre-command audit. The release
result is **command submitted**, not verified final mailbox placement.

Unit tests exercise 55-recipient truncation, malformed IDs, incomplete
inventory and duplicate queue IDs without invoking Postfix. Real host
qualification and a least-privilege queue helper remain outstanding.
