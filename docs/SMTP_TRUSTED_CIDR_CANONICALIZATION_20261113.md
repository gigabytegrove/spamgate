# Native SMTP trusted-CIDR canonicalization — 2026-11-13

## Defect and security consequence

The native SMTP listener accepted `SPAMGATE_SMTP_TRUSTED_CIDRS` using `net.ParseCIDR`, which silently masks host bits. An operator entering `192.0.2.5/24` could therefore trust every address in `192.0.2.0/24` rather than the single intended peer. This matters because trusted peers can submit mail to the native SMTP listener and supply XFORWARD identity.

## Correction

`parseSMTPTrustedNetwork` requires canonical network prefixes. A host address without a slash retains existing conversion to `/32` (IPv4) or `/128` (IPv6). Explicit `192.0.2.5/32` and `2001:db8::5/128` remain valid. A network such as `192.0.2.0/24` remains valid. Non-canonical `192.0.2.5/24` and `2001:db8::5/64` now fail configuration instead of broadening trust. No mail server is reconfigured automatically.

## Evidence

- Inspected `main` at `c4850d07d7af8bad1efa715cbf95874a23d01e8e` and the complete native SMTP listener implementation.
- Committed listener integration, new parser and regression tests in three separate commits.
- An isolated Go 1.23.2 reproduction of the parser passed eight IPv4/IPv6 canonicalization cases; this is **not** execution of the repository's test suite.
- The GitHub connector's commit workflow lookup returned an empty list, but it filters to pull-request-triggered runs and cannot establish whether push CI ran.
- Local GitHub clone remains blocked by DNS resolution, so exact-HEAD compilation, repository tests and push CI completion are **unverified**.
- No real Postfix/Dovecot/ISPConfig mail host was accessed.

## Operational compatibility

An existing configuration containing host bits in a CIDR prefix will now refuse listener initialization. Operators must explicitly choose either the intended canonical network or a single-host address. This is a deliberate fail-closed change, not an automatic rewrite of a production configuration.

## Remaining gates

Issues #1–#9 remain open: real Postfix/Dovecot disposition and holds, crash/disk-full/acknowledgment durable delivery, SMTP/authentication interoperability, classifier precision/recall and false-positive corpora, full tenant lifecycle, retained diagnostics and alerts, complete browser acceptance, backup/restore and native update/rollback. The locked architecture remains `/opt/spamgate/spamgate` foreground, `spamgate-worker`, persistent `/opt/spamgate/data`, Milter ports 38470/38472, native Linux without Docker substitution. No production host was modified and no beta qualification is claimed.
