# Native SMTPUTF8 header and envelope preflight — 2026-10-30

## Scope

The outbound native SMTP relay must not silently send RFC 6532 raw UTF-8
headers to an ESMTP peer that only advertises 8BITMIME. RFC 6152 permits
eight-bit body octets without requiring SMTPUTF8, but RFC 6532 raw UTF-8
headers require SMTPUTF8 in addition to 8BITMIME. ASCII RFC 2047 encoded-word
headers do not require SMTPUTF8.

Before MAIL FROM, SpamGate now inspects the immutable RFC 5322 header section
and checks every persisted envelope path. Invalid UTF-8 in raw headers, NUL
headers, invalid UTF-8 envelope paths, empty recipients, and CR/LF/NUL in
envelope paths stop delivery before an SMTP transaction begins. This prevents
corrupt queue records from being transmitted and preserves the durable original.

The upstream must advertise SMTPUTF8 and 8BITMIME for RFC 6532 headers or
internationalized envelope addresses. 8BITMIME alone suffices for eight-bit
body data with ASCII headers and ASCII envelope addresses. No message is
silently downgraded, transcoded, or rerouted. An unsupported relay remains a
retryable configuration error; operators can fix the upstream relay without
discarding the original.

## Evidence

- Table-driven tests cover ASCII, raw UTF-8, folded headers, LF-only fixtures,
  encoded-word headers, invalid UTF-8 and NUL, null reverse paths, malformed
  recipient paths, and missing recipients.
- TCP protocol tests verify no MAIL FROM occurs on an unsupported relay and
  valid RFC 6532 headers can be transmitted to a compliant test peer.
- Run `go test -count=1 ./internal/transport`, `go test -race ./...`,
  `go vet ./...` and the native qualification workflows at the exact commit.

## Still outstanding

This is a focused outbound conformance improvement, not certification of
SMTPUTF8 interoperability with third-party MTAs. It does not change the
Postfix Milter ports, service architecture, native launcher, or running
production mail host. The SMTP content-filter listener does not yet advertise
SMTPUTF8, and end-to-end internationalized mailbox placement still requires
live Postfix/Dovecot qualification. All production gates #1–#9 remain open.
