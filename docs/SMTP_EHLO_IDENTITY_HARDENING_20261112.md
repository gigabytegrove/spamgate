# SMTP EHLO evidence hardening — 2026-11-12

Scope: `internal/smtpprobe` diagnostic only. The first EHLO reply line identifies the server; it is not an extension advertisement. The probe previously interpreted that line as a capability, allowing a server identity of `STARTTLS` to trigger an unsupported TLS upgrade attempt or an identity beginning `AUTH` to be recorded as authentication evidence.

The parser now skips the identity line, accepts STARTTLS only as a bare extension, validates AUTH mechanism token characters and length, normalizes case, and deduplicates mechanisms in stable advertisement order. It retains the existing AUTH= extension compatibility behavior. No authentication, envelope, DATA, or mail-server configuration changes are introduced.

Regression source: `internal/smtpprobe/capabilities_security_test.go` covers identity-only capability spoofing, valid advertisements, duplicates, invalid mechanism tokens, oversized tokens and empty replies.

Qualification boundaries: isolated CI may validate code and simulated SMTP behavior, but does not certify live Postfix/Dovecot mailbox disposition, authenticated submission, tenant policies, durable delivery, backup/restore or update rollback. All issues #1–#9 remain open. Permanent native launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, data `/opt/spamgate/data` and Milter ports 38470/38472 are unchanged.
