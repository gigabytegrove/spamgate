# XFORWARD HELO invalid-result integrity — 2026-11-14

## Finding
The address-literal branches of parseSMTPXForwardHelo returned the original wire value alongside false on invalid IPv4 or IPv6 literals. The SMTP handler already checks the boolean and rejects invalid values, so this is a defense-in-depth contract correction, not evidence of an existing authentication bypass. DNS-label branches already returned empty on failure.

## Change
All invalid HELO identities now return ("", false). Valid DNS and IP literals, and explicit unavailable markers, preserve previous behavior. Regression tests cover malformed IPv4, malformed IPv6, mapped IPv6, zone identifiers, delimiters and the return-value invariant. A Go fuzz entry point seeds valid and invalid examples.

## Qualification
Local checkout failed because github.com DNS resolution was unavailable. No local Go tests or vet ran. Exact-HEAD GitHub Actions and isolated Postfix/Dovecot lab must be inspected separately; a committed test is not a passing test. No production mail server was modified. Issues #1–#9 remain open and October 31 beta target was missed.

## Architecture
Keep /opt/spamgate/spamgate foreground launcher, spamgate-worker, persistent /opt/spamgate/data, native Linux, and Postfix Milter ports 38470/38472. No Docker substitution or automatic running mail-server changes.
