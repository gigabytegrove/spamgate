# Rspamd HTTP preflight status integrity — 2026-11-14

## Root cause
The compatibility handler selected HTTP 400 versus 415 by searching for the substring `Helo` in an error message. This coupled protocol status to diagnostic wording. An encoding error whose wording changed could be misclassified as malformed SMTP identity, or vice versa.

## Correction
Preflight now returns typed, inspectable error causes. Unsupported `Compression` or `Content-Encoding` is HTTP 415; invalid HELO is HTTP 400; unknown preflight errors fail closed as HTTP 400. Validation runs before reading the MIME body, scanning, or persistence. The supported encodings and HELO grammar are unchanged.

## Evidence and limitations
Added table-driven error-cause/status tests and handler-level assertions that rejected requests do not consume their body. These are source-level regression guards, not evidence of full Postfix/Dovecot qualification. Production SMTP delivery, classifier accuracy, tenant policies, browser workflows, native backup/restore and update/rollback still require end-to-end qualification. The native launcher, worker, data path and Milter ports remain unchanged.
