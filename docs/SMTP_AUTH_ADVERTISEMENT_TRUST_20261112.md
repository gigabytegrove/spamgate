# SMTP AUTH advertisement trust — 2026-11-12

## Scope and observed behavior

The read-only SMTP probe treats advertised mechanisms as evidence only when exactly one syntactically valid AUTH extension is present. Both `AUTH PLAIN LOGIN` and legacy `AUTH=PLAIN LOGIN` are accepted. Empty, duplicate, mixed-form, and partially malformed advertisements produce an empty trusted mechanism list. This prevents an invalid line from being silently discarded while another valid token is promoted as evidence.

STARTTLS advertisement trust remains independent: malformed AUTH cannot prevent a separately trustworthy STARTTLS upgrade. The probe sends EHLO and, where advertised, STARTTLS and a second EHLO; it never issues AUTH, MAIL FROM, RCPT TO, DATA, BDAT, or credentials.

## Regression source

- `internal/smtpprobe/auth_trust_test.go`: 11 table-driven AUTH advertisement scenarios and independent STARTTLS trust test.
- `internal/smtpprobe/auth_trust.go`: single-advertisement trust policy.
- `internal/smtpprobe/capabilities.go`: fail-closed application of the trust policy.

## Qualification boundaries

This is parser hardening, **not** evidence of SMTP AUTH interoperability, credential acceptance, TLS policy compliance, delivery, or production mail-host qualification. All production gates #1–#9 remain subject to end-to-end acceptance. The permanent foreground launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, persistent data `/opt/spamgate/data`, and Milter ports 38470/38472 are unchanged. No live mail-server settings are altered.

Run `go test ./internal/smtpprobe -count=1` and repository-wide qualification in CI; record exact commit outcomes before promoting this change. Real-host tests must be separately authorized and documented.
