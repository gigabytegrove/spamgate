# SMTP numeric rejection diagnostics — 2026-11-18

Issue #6: typed SMTP reply failures at greeting, EHLO, STARTTLS, and post-TLS EHLO.

The probe now retains the stage and numeric SMTP response code in a typed error, without carrying remote response text. 4xx responses map to SMTP_TEMPORARY_REJECTION; 5xx map to SMTP_PERMANENT_REJECTION; other unexpected responses map to SMTP_UNEXPECTED_REPLY. Operator findings remain fixed, sanitized strings. Timeouts, DNS, and TLS verification errors continue to use existing categories.

The tests exercise wrapped typed errors and a real loopback TCP listener returning a 421 greeting. They do not authenticate to a real MTA, exercise mail disposition, or certify a production mail host. This change is read-only: no mail-server configuration, listener, supervisor, or worker settings are modified.

Qualification required: repository Go tests, race tests, CI, disposable Postfix/Dovecot lab, and separate production-host acceptance. Issues #1–#9 remain open pending their independent gates.
