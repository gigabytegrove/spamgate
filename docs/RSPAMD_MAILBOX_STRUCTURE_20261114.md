# SMTP mailbox structural validation — 2026-11-14

## Observed defect and correction
The previous native Rspamd-compatible HTTP request parser only required the last `@` to have characters on either side. It therefore accepted ambiguous identities such as `a@b@example.test`, whitespace in unquoted local parts and domains, and invalid domain-label boundaries. The new `rspamdValidateMailboxStructure` helper runs after SMTP path-wrapper handling and before scanning. It recognizes quoted local parts, escaped quoted-pair characters and bracketed domain literals while rejecting malformed separators, domain labels, invalid UTF-8 and control characters.

## Files
- `internal/transport/rspamd_mailbox_structure.go`: new structural validator.
- `internal/transport/rspamd_mailbox_identity.go`: invokes validator.
- `internal/transport/rspamd_mailbox_structure_test.go`: twenty table-driven boundary cases.

## Qualification limits
This is a conservative mailbox boundary, not full RFC 5321/6531 interoperability certification. In particular, domain literals are structurally checked, not verified as IPv4/IPv6 addresses; internationalized domains require an explicit IDNA policy. Test cases are committed; exact-HEAD GitHub engineering and isolated mail-lab workflows must finish before claiming integrated regression. No production mail host has been accessed or modified. The October 31 beta target has passed, and issues #1–#9 remain qualification gates.

## Architecture
Keep native `/opt/spamgate/spamgate` foreground launcher, `spamgate-worker`, persistent `/opt/spamgate/data`, and Postfix Milter ports 38470/38472. No Docker substitution and no automatic running mail-server changes.
