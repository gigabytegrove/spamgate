# STARTTLS ambiguity fail-closed evidence — 2026-11-12

## Scope
The read-only SMTP probe now refuses to treat duplicated or parameterized STARTTLS EHLO extensions as a trustworthy TLS upgrade capability. This prevents a valid STARTTLS line from masking an inconsistent second advertisement. The first EHLO identity line is excluded. Case-insensitive bare STARTTLS remains supported.

The existing probe rejects a required-TLS connection if STARTTLS is not trustworthy; optional-TLS diagnostics return without attempting authentication, MAIL FROM, RCPT TO, or DATA. EHLO warning codes remain available to distinguish malformed and duplicate extensions. No mail-server configuration or native runtime layout was changed.

## Test coverage
`internal/smtpprobe/starttls_trust_test.go` covers valid, missing, identity-only, case-insensitive, duplicate, parameterized, and mixed valid/malformed capability lines. These are source-level regressions; successful execution must be established by exact-commit CI.

## Qualification gaps
This is not SMTP transaction compliance or production host qualification. Issues #1–#9 remain open, including real Postfix/Dovecot disposition, durable delivery, classifier false-positive measurements, tenant enforcement, operational UI, cold restore, native update/rollback, and mail-host acceptance. Preserve `/opt/spamgate/spamgate`, `spamgate-worker`, `/opt/spamgate/data`, and ports 38470/38472.
