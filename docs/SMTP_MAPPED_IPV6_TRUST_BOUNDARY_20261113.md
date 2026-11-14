# SMTP mapped IPv6 trusted-network boundary (2026-11-13)

The native SMTP listener's `SPAMGATE_SMTP_TRUSTED_CIDRS` parser rejects IPv4-mapped IPv6 CIDRs such as `::ffff:192.0.2.0/120` and `::ffff:c000:200/120`. Go's IP address handling normalizes mapped IPv6 addresses to IPv4 in several operations, including network membership. Operators must specify `192.0.2.0/24` for IPv4 peers, and native IPv6 prefixes for native IPv6 peers. This is a configuration validation change, not a change to any running Postfix instance.

## Verification and limits

Regression cases were added to `internal/transport/smtp_trusted_network_test.go`. An exact-HEAD Go test and isolated Postfix/Dovecot workflow must pass before this revision is considered qualified. Existing IPv4 `/32`, IPv4 network, native IPv6 `/128` and native IPv6 network policies remain accepted. This does not qualify live mail-host ingress, Milter dispositions, crash durability, tenant routing, backup/restore or native update/rollback. No live mail-server configuration is changed.
