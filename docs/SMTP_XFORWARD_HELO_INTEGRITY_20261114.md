# SMTP XFORWARD HELO identity integrity — 2026-11-14

## Change
Trusted Postfix XFORWARD HELO is now validated before being used as the original SMTP HELO identity for SPF evaluation. Accept ASCII DNS LDH labels and bracketed IPv4 / tagged IPv6 literals; preserve case and the original token. Reject empty, malformed, overlength, whitespace, non-ASCII, control characters, IPv6 zones and IPv4-mapped IPv6 literals. Recognize the Postfix unavailable markers without treating them as real hostnames.

This is a deliberately strict compatibility boundary. A real mail host may legitimately send non-DNS HELO strings. Such hosts must be identified through an isolated Postfix integration test and the policy revisited before deployment. Do not automatically alter Postfix or Dovecot configuration.

## Verification and beta qualification
Source and tests committed; GitHub Actions result must be checked on the final commit. Tests cover DNS labels, address literals, unavailable markers, injection and length limits. Real mail-host XFORWARD interoperability and SPF result equivalence remain unverified.

## Locked architecture
Permanent foreground launcher /opt/spamgate/spamgate, spamgate-worker, persistent /opt/spamgate/data, native Linux, Postfix Milter ports 38470 and 38472. No Docker substitution, no running mail-server modification.

## Remaining production gates
Issues #1–#9 remain subject to full qualification: Postfix/Dovecot dispositions and holds; durable delivery crash and disk-full injection; SMTP and authentication interoperability; classifier false-positive cohorts; tenant enforcement; diagnostics; complete browser UI; backup/restore; native update and rollback. The October 31 beta target passed; do not claim beta readiness without end-to-end host evidence.
