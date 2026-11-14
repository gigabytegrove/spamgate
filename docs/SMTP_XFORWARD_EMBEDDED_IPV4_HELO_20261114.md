# XFORWARD HELO embedded IPv4 validation — 2026-11-14

## CI failure and correction

Engineering workflow 43569161272 failed `TestParseSMTPXForwardHelo/[IPv6:2001:db8::ffff:192.0.2.5]`: Go's `netip.ParseAddr` correctly accepts a dotted-quad tail in an otherwise native IPv6 address. `Is4In6` rejects only IPv4-mapped addresses in the `::ffff:0:0/96` range, not every IPv6 address containing dotted-quad notation. The earlier test expected rejection, while the implementation allowed the valid but noncanonical textual representation.

The HELO parser now explicitly refuses dotted-quad tails in IPv6 address literals, consistently requiring hexadecimal IPv6 presentation. This is a deliberately strict identity policy, not a claim that the dotted-quad representation is invalid IPv6 syntax. New regression cases cover mapped and nonmapped embedded IPv4 tails and assert that rejection never returns the untrusted value.

## Boundaries

This only affects trusted Postfix XFORWARD HELO metadata; it does not change the XFORWARD ADDR parser or SMTP relay transport. Existing valid hexadecimal IPv6 literals, bracketed IPv4 literals, and DNS greetings remain supported. Real Postfix interoperability, SPF behavior and production-host acceptance remain unqualified. No mail-server configuration or runtime service is changed.
