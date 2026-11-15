# SMTP diagnostic failure-stage evidence — 2026-11-15

The read-only native SMTP probe now returns `failure_stage` and a stable, sanitized finding when an operation fails. The original Go error is still returned to the caller; the structured finding is not a substitute for safe error handling. Stages are configuration, connection, greeting, ehlo, tls_policy, starttls, tls_handshake and post_tls_ehlo. Findings contain no server response body, peer address, credentials, or certificate identity.

A TLS-required probe that receives a successful EHLO without STARTTLS records `SMTP_TLS_REQUIRED_UNAVAILABLE`, while preserving the separate `STARTTLS_NOT_ADVERTISED` observation. It never proceeds to plaintext authentication. A rejected greeting cannot establish an AUTH-policy conclusion.

Tests cover configuration failure, a local TCP peer rejecting the greeting, TLS-required downgrade refusal and finding privacy. They are regression source tests, not evidence of SMTP authentication enforcement on a real production mail host.

This does not change the native launcher (/opt/spamgate/spamgate), worker (spamgate-worker), persistent data (/opt/spamgate/data), or Postfix Milter ports 38470/38472. No running mail server is modified.

Acceptance remains open: exact-HEAD Go tests/CI, isolated Postfix/Dovecot laboratory, representative fault injection and independent production-host qualification. The October 31 beta deadline has passed without production qualification.
