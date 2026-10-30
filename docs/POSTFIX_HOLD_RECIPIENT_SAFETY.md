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

## Null-reverse-path held delivery status notifications

A genuine SMTP `MAIL FROM:<>` is a valid sender identity, including for
delivery status notifications. The release endpoint now allows a held
null-sender message **only** when the scanned envelope and live Postfix
queue inventory both have a null sender. A non-null/null mismatch still
fails closed. Existing queue ID, arrival-time, complete-recipient,
single-record and durable pre-command audit checks remain mandatory.
A regression verifies mismatch refusal, one permitted release and
duplicate-release refusal without invoking a real production `postsuper`.
