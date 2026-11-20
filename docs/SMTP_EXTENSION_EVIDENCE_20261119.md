# SMTP extension evidence — 2026-11-19

Scope: issue #3 SMTP compliance and issue #6 diagnostics. This is read-only EHLO inspection, not an SMTP submission or delivery test.

The probe now captures parameterless PIPELINING, 8BITMIME, SMTPUTF8, CHUNKING, DSN, and REQUIRETLS advertisements before and after verified STARTTLS. Identity lines, malformed parameters, whitespace anomalies, and duplicate advertisements are not promoted to trusted extension evidence. Changes after TLS are informational observations, suppressed when either side's evidence is ambiguous.

Safety: no AUTH credentials, MAIL FROM, RCPT TO, DATA, BDAT, or server configuration changes. Existing launcher, worker, persistent data path, and Milter ports remain untouched.

Verification required: complete repository Go tests and race tests, exact-HEAD engineering CI, isolated Postfix/Dovecot lab, and independent live production mail-host acceptance. This change alone does not close issue #3 or #6. All issues #1–#9 remain production gates.
