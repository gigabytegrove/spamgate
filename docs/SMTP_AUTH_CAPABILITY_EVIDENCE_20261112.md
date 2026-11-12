# SMTP AUTH capability evidence — 2026-11-12

Issue #3/#6 incremental work. The read-only relay probe now reports advertised AUTH mechanisms as a bounded, deduplicated list and distinguishes an empty AUTH extension from a usable mechanism advertisement. The SMTP greeting identity is not interpreted as an extension. The probe never sends AUTH, MAIL FROM, RCPT TO or DATA. It does not establish successful authentication, credential compatibility, delivery, or production Postfix/Dovecot qualification.

Tests exercise the capability parser, benign/malformed extension tokens, an SMTP socket fixture with AUTH/no AUTH/empty AUTH, and assert that no mail or authentication commands are sent.

Unverified: real relay mechanisms and authentication, actual message delivery, final-HEAD CI and live mail-host acceptance until independently observed. The native foreground launcher, worker, data directory, Milter ports and mail-server configuration are unchanged.
