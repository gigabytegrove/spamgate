# Native SMTP relay capability preflight — October 30, 2026

Scope: issue #3 (SMTP protocol interoperability), with issue #2 (durable originals) and #4 (recipient safety) implications.

## Behavior

The outbound relay validates the actual post-EHLO capabilities of the configured next hop, after STARTTLS when required and **before** issuing MAIL FROM:

| Original / envelope | Required advertised extension | Incompatible relay |
| --- | --- | --- |
| Seven-bit RFC 5322 bytes, ASCII reverse path and recipients | No ESMTP extension required | Normal delivery |
| Any original octet >= 0x80 | 8BITMIME | Retryable delivery failure; original remains in durable spool |
| Non-ASCII SMTP envelope sender or recipient | SMTPUTF8 | Retryable delivery failure; original remains in durable spool |
| Advertised numeric SIZE limit below original byte length | SIZE preflight | Retryable delivery failure; original remains in durable spool |
| Malformed advertised SIZE parameter | Valid numeric SIZE parameter | Retryable delivery failure; original remains in durable spool |

No silent MIME re-encoding, SMTPUTF8 address downgrade, or mutation of accepted original bytes is attempted. A missing capability is not represented as a server-issued SMTP 5xx, so the queue's permanent-failure classifier does **not** discard the original. Operator action may be required to select a compatible next hop; repeated retries do not make an incompatible relay compatible.

## Verification

`internal/transport/relay_capabilities_test.go` covers ASCII, eight-bit body/header, internationalized sender/recipient and null reverse path. `internal/transport/relay_capabilities_tcp_test.go` exercises a real TCP SMTP server that advertises various EHLO extensions and asserts that incompatible messages are refused **before MAIL FROM**. Existing relay and queue tests remain in CI.

## Explicit limitations / outstanding acceptance

- This is a preflight check, not third-party SMTPUTF8/8BITMIME interoperability certification.
- The code does not transform MIME content or normalize internationalized domain names. Address validation remains an independent acceptance gate.
- The existing queue has at-least-once semantics. A remote SMTP 250 followed by local crash can duplicate mail.
- Per-recipient remote RCPT responses remain transaction-scoped. Mixed accepted/rejected recipient sets require explicit safe policy, split/fallback design and real-host qualification before issue #4 can close.
- DSN generation, SPF/DKIM/DMARC/ARC external corpus qualification, live Postfix/Dovecot disposition, real browser acceptance and cold restore are not completed by this change.
- The production Postfix `milter_default_action = accept` is unchanged. No mail host configuration or running service is changed.

## Operator checks (read-only)

Use the existing SMTP EHLO/STARTTLS diagnostics to verify that the configured next hop advertises 8BITMIME, SMTPUTF8 and a sufficient SIZE limit. Compare the negotiated extensions after STARTTLS; pre-TLS advertisements may differ. If the relay lacks a required extension, correct the upstream route or policy rather than manually editing immutable spool records.
