# Rspamd HTTP request-body failure boundaries — 2026-11-14

## Implemented
The native HTTP compatibility worker validates the claimed SMTP client IP before consuming request body bytes. It rejects declared Content-Length above 10 MiB before reading, while retaining MaxBytesReader for streaming and chunked requests. MaxBytesError is reported as HTTP 413; other body read failures are HTTP 400, not mislabeled as size violations. The scanner and persistent store are not reached on these failures.

Regression tests cover invalid mapped IPv6 identity with an unreadable body, early declared-size refusal, interrupted body reads, and unknown-length streaming oversize. These tests exercise the actual handler, not a copied validator.

## Qualification boundary
This change does not implement SMTP delivery retries or certify accepted originals. Postfix/Dovecot production evidence, mail spool crash injection, tenant conflict handling, classifier corpus metrics, UI browser acceptance, native restore, and update/rollback remain open under issues #1–#9. No running mail-server configuration was changed. Locked native layout remains /opt/spamgate/spamgate, spamgate-worker, /opt/spamgate/data, and Milter ports 38470/38472.

## Verification
The repository commit and source were written via GitHub. Full Go tests, race tests, and exact-HEAD Actions completion must be checked independently; do not infer a pass from committed test source.
