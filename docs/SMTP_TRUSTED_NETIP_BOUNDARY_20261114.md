# SMTP trusted-network CIDR parsing — 2026-11-14

## Scope
Native SpamGate SMTP trusted-peer access control only. This is not a change to the mail server's running configuration or to Milter ports 38470/38472.

The parser now uses Go net/netip to validate the original address and prefix without legacy net.ParseCIDR normalization. It converts an accepted prefix to net.IPNet for existing callers, preserving their interface. Explicit canonical IPv4 and IPv6 networks and single-host prefixes remain supported. Host-bit CIDRs, mapped IPv6, dotted-quad IPv6, zones, malformed masks, and surrounding whitespace fail closed. The existing SMTPFromEnv integration continues to use this parser.

## Evidence and boundaries
An isolated Go 1.23.2 package test executed successfully for 16 representative boundary cases and go vet completed without findings before the source change was committed. The repository regression suite and new expanded cases must still pass on exact-HEAD CI. Isolated parser execution does not qualify real Postfix forwarding, XFORWARD behavior, live mail disposition, SMTP authentication, or ISPConfig deployment.

## Production gates
Issues #1–#9 remain open. Do not close any based on this parser correction. Next acceptance must include exact-HEAD engineering and Postfix/Dovecot lab results, host-level trust-boundary tests, durable acceptance crash/failure injection, classifier false-positive corpora, tenant policy isolation, browser regression, and native backup/update/rollback. No running mail server was modified.
