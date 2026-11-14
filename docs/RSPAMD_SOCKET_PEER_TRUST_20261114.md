# Rspamd HTTP socket-peer address family enforcement — 2026-11-14

## Security boundary
The Rspamd-compatible HTTP worker authenticates the actual TCP peer before checking its optional bearer token or routing requests. The previous handler used net.ParseIP followed by net.IPNet.Contains, which can normalize IPv4-mapped IPv6 peer addresses into IPv4 addresses. An IPv4 ACL therefore could inadvertently authorize a mapped IPv6 socket representation.

The new rspamdPeerTrusted helper parses the actual RemoteAddr with net.SplitHostPort and netip.ParseAddr, rejects IPv4-mapped IPv6 and zone-qualified addresses, and checks membership only after the address family is unambiguous. Forwarded, X-Forwarded-For and similar HTTP headers are not used to establish trust. Missing ACLs, malformed peers and nil ACL entries fail closed.

## Compatibility
Ordinary IPv4 and native IPv6 TCP peers remain supported. A reverse proxy must be explicitly represented by its actual canonical peer address in the worker's trust list. Mapped IPv6 socket peers are intentionally denied even if their embedded IPv4 address belongs to an allowed IPv4 network.

## Evidence and outstanding gates
Added unit cases for IPv4, IPv6, mapped IPv6, malformed, zone-qualified and absent peers; HTTP-handler regression cases assert denial occurs before bearer authentication. These tests are source coverage, not production host qualification. No running Postfix, Dovecot, ISPConfig, or native systemd service was modified.

All GitHub issues #1–#9 remain subject to independent acceptance, including real Postfix holds and Sieve disposition, durable delivery failure injection, SMTP authentication, classifier false-positive measurement, tenant policies, diagnostics, complete browser workflows, backup/restore, and native upgrade/rollback. The October 31 beta target has passed; this change does not qualify the beta.
