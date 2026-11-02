# Native Milter queue identity and callback integrity — 2026-11-02

Production gates: [#1](https://github.com/gigabytegrove/spamgate/issues/1) (Postfix/Dovecot disposition), [#3](https://github.com/gigabytegrove/spamgate/issues/3) (protocol compliance), and [#6](https://github.com/gigabytegrove/spamgate/issues/6) (diagnostic evidence).

## Failure modes

Previously, the Milter callback handler accepted a valid Postfix queue-ID macro in one `D` frame and silently replaced it with a different valid ID from a later `D` frame in the same SMTP transaction. The saved scan could then be correlated to the wrong Postfix queue entry. This is especially unsafe when the administrator later considers releasing a held original. The parser also treated arbitrary extra braces around `i` as a legitimate queue-ID macro.

The native Milter now retains one unambiguous queue ID per MAIL FROM transaction. Repeated identical values are allowed; conflicting values poison that transaction and cause an SMTP temporary-failure request at end-of-message, without saving an incorrect scan-to-queue association. The next MAIL FROM starts with fresh queue evidence. Macro names must be exactly `i` or `{i}`.

The client-IP callback now requires a single, complete, NUL-terminated IP address with no trailing data or embedded terminator; malformed address evidence is not used as the client's IP. Header callback names now reject RFC 5322 forbidden spaces and colon characters as well as control characters. Existing valid IPv4/IPv6 and folded-header behavior is preserved.

## Regression execution

```bash
go test -count=1 ./internal/transport -run 'TestMilter(ConflictingQueueIDMacrosTempfailAndRecover|QueueIDMacroNameDoesNotAcceptExtraBraces|ClientAddressRequiresExactTerminatedIP|HeaderFieldNameRequiresRFC5322PrintableNoColon)' -v
go test -count=1 ./...
go test -race -p 1 -count=1 ./...
```

These tests use an in-process Milter wire connection and temporary Store, not the installed MTA. No production Postfix/Dovecot, ISPConfig, mail data, service configuration, or running process is changed.

## Qualification limits

A requested Milter temporary failure is not proof that Postfix enforced it. Queue-ID macros are supplied by the trusted MTA, not cryptographically authenticated. Invalid IP callbacks currently omit the client-IP evidence; this alone does not prove SPF or DMARC enforcement. The tests do not replace the real Postfix/Dovecot acceptance matrix, adversarial multi-recipient/reused-ID live tests, production hold-release evidence, or independent RFC interoperability. All nine cumulative production gates remain open, and the missed October 31 beta target remains unmet.

Architecture remains unchanged: foreground `/opt/spamgate/spamgate`, `spamgate-worker`, persistent `/opt/spamgate/data`, Postfix Milter ports 38470/38472; no Docker substitution and no automatic changes to the running mail server.
