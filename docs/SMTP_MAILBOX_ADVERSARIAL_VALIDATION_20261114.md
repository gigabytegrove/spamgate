# SMTP mailbox identity hardening — 2026-11-14

Scope: native Rspamd-compatible HTTP transport only; no mail-host configuration changes.

## Changes
- Enforce SMTP mailbox local-part length (64 octets), dot-atom boundaries, and quoted-string placement.
- Validate IPv4 and tagged IPv6 address literals using Go net.ParseIP rather than accepting arbitrary bracket contents.
- Reject C1 controls and malformed UTF-8 while retaining valid UTF-8 local parts without normalization.
- Add adversarial mailbox regression coverage for spoofed separators, malformed quotes, IP literals, Unicode, and byte limits.

## Safety and compatibility
This deliberately does not rewrite envelope recipients, split multi-recipient transactions, or modify the running MTA. The parser is not a full RFC 5321/6531 grammar implementation. Domain-literal IPvFuture and other SMTP general-address-literal forms are not supported; test actual sender compatibility before enabling strict transport checks in production.

## Qualification
GitHub commits confirm source changes only. Full native Go tests, CI final-head completion, Postfix/Dovecot interoperability, false-positive corpus, and real-host delivery qualification must be independently verified. Issues #1-#9 remain open. No beta readiness claim.
