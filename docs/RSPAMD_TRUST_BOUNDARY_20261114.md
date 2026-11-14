# Rspamd-compatible HTTP trust boundary — 2026-11-14

## Change

The native Rspamd-compatible worker previously used `net.ParseCIDR` directly. That API silently masks host bits: `192.0.2.5/24` became trust for the entire `192.0.2.0/24`. It also allowed IPv4-mapped IPv6 declarations that are ambiguous at the Go IP comparison boundary.

The worker now delegates ACL parsing to `parseRspamdTrustedNetworks`, which shares the canonical CIDR policy with the native SMTP listener. Literal IPv4 and IPv6 host addresses remain supported as /32 and /128. The parser refuses host bits in network prefixes, mapped IPv6, embedded dotted IPv4 in IPv6, zone identifiers, empty entries, duplicate entries, malformed prefixes and more than 128 entries.

The default `127.0.0.1/32,::1/128` remains valid. The HTTP listener, API paths, scanner, token behavior, systemd layout, Postfix Milter ports and persistent data root are unchanged. This change may intentionally reject previously accepted ambiguous operator configurations; correct these to explicit canonical network prefixes before restarting.

## Evidence and remaining gates

New table-driven tests exercise positive membership, negative membership and malformed declarations. These tests are source coverage, not evidence of actual host deployment until the exact commit CI succeeds.

No production mail server, ISPConfig, Dovecot, Postfix or persistent queue was changed. Live Rspamd client interoperability, real mail disposition, durable failure injection, classifier false-positive calibration, complete UI, backup/restore and native update/rollback remain unqualified. Issues #1–#9 must not be closed based on this change.
