# Native Milter envelope identity and callback sequencing (2026-11-02)

This change hardens the existing native Postfix Milter v6 listener without altering its ports, service topology, Postfix configuration, or message-disposition defaults.

## Failure mode

The prior MAIL FROM / RCPT TO callbacks used a first-NUL string extractor that accepted missing terminators, truncated extra data, stripped unmatched path delimiters, and silently discarded invalid/empty recipients. A second MAIL callback reset the in-progress transaction, even after an earlier callback had already poisoned it. CONNECT/HELO callbacks could also replace the client identity mid-message. The CONNECT address parser did not enforce the declared IPv4/IPv6 family.

## Behavior

* MAIL and RCPT must contain a complete NUL-terminated path; additional bounded, printable NUL-terminated ESMTP arguments remain supported.
* The explicit null reverse path \`<>\` is accepted for MAIL only; empty RCPT, malformed UTF-8, control/whitespace injection, unbalanced brackets, missing terminators, and empty/oversized ESMTP arguments are rejected.
* A repeated MAIL before EOM/ABORT, or a CONNECT/HELO callback after MAIL, poisons the transaction and requests SMTP temporary failure. An EOM/ABORT boundary clears the poisoned state; an intervening MAIL cannot.
* CONNECT address families must agree with their parsed IP literal.

## Verification and limitations

The new Go regression tests exercise malformed and valid wire envelopes, SMTPUTF8 byte validation, ESMTP arguments, cross-callback mutation, recovery, and IPv4/IPv6 family mismatch. These are in-process wire tests, not independent production Postfix qualification. The parser validates callback integrity; it does not independently authenticate the MTA or prove Postfix disposition, Dovecot placement, or end-to-end SMTP interoperability. Postfix Milter peer trust remains controlled by \`SPAMGATE_MILTER_TRUSTED_CIDRS\`.

This is a fail-temporary policy for malformed or contradictory callbacks; no running mail server is automatically changed. Issue #1, #3, and #6 production gates remain open pending real-host evidence.
