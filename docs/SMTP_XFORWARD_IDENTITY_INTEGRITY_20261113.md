# SMTP XFORWARD identity integrity — 2026-11-13

The native SMTP listener rejects unknown XFORWARD keys instead of acknowledging
them without recording their contents. ADDR now uses strict balanced-bracket
validation, optional Postfix IPv6: prefix validation, and IP parsing. The
canonical parsed IP is recorded, not a loosely trimmed input string.

Accepted: IPv4, IPv6, bracketed IPv4, bracketed IPv6, and IPv6:-prefixed IPv6.
Rejected: unbalanced or repeated brackets, malformed IPv6: prefixes, zone IDs,
control characters and non-IP addresses. Duplicate ADDR/HELO, transaction
ordering and existing trusted-peer checks remain enforced.

This is source-level hardening, not proof of Postfix interoperability. The
required follow-up is a live Postfix XFORWARD transaction, including rejection
and valid IPv4/IPv6 identity propagation, plus exact-commit regression CI.
No running mail server is reconfigured by this change.
