# SMTP AUTH capability comparison — 2026-11-11

## Scope

The native read-only `spamgate-smtp-probe` now compares the mechanisms advertised in the initial EHLO with those returned by the second EHLO after a **verified** STARTTLS handshake. Mechanism comparison is case-insensitive and duplicate-insensitive.

- `AUTH_NOT_ADVERTISED_AFTER_TLS` (warning): AUTH was initially advertised, but no mechanisms were advertised in a successful post-TLS EHLO.
- `AUTH_MECHANISMS_CHANGED_AFTER_TLS` (info): some initially advertised mechanisms disappeared after a successful post-TLS EHLO, while others remained.
- No capability-change finding is emitted if TLS verification failed, the second EHLO failed, or no AUTH mechanisms were initially advertised.
- `AUTH_ADVERTISED_BEFORE_TLS` remains a warning requiring operator verification; it does **not** assert that plaintext credentials can be submitted.

The probe never authenticates, sends credentials, submits mail, or changes Postfix/Dovecot settings. These observations do not prove SMTP AUTH interoperability, message disposition, or production compliance.

## Regression coverage

`internal/smtpprobe/assessment_mechanisms_test.go` covers normalization/deduplication, partial disappearance, full disappearance, case-insensitive retention, failed post-TLS EHLO, unverified TLS, and no initially advertised AUTH.

Run `go test ./internal/smtpprobe ./cmd/spamgate-smtp-probe` and the repository's engineering and Postfix/Dovecot workflows against the **exact final commit**. Do not claim those gates passed until their results are inspected.

## Remaining qualification

Issues #1–#9 remain open. In particular, independent real mail-host evidence, SMTP authentication attempts using safe test credentials in an isolated environment, protocol conformance fixtures, classifier false-positive measurements, durable delivery fault injection, browser workflows, backup/restore, and native update/rollback remain outstanding. The October 31 beta target was missed.
