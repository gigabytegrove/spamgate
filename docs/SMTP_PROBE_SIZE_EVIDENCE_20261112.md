# Independent SMTP probe SIZE evidence — 2026-11-12

Scope: issues #3 (SMTP compliance) and #6 (operational diagnostics). This change only reads successful EHLO advertisements. It never sends MAIL FROM, RCPT TO, DATA, AUTH or a message body and does not change Postfix, Dovecot or SpamGate's native service topology.

The probe exposes size_advertised, size_limit_known, size_limit_bytes, size_warning and independent post_tls_size_* fields. A SIZE extension without a number is advertised but has no known maximum. A numeric zero is known and must not be conflated with an unspecified maximum. Numeric limits are unsigned decimal uint64 values. Extra parameters, signs, decimal points, overflow, oversized tokens, and duplicate SIZE declarations are not trusted as numeric limit evidence. The first EHLO reply line is the server identity and cannot be used as extension evidence.

The SIZE warning is observational; it does not claim delivery failure, authentication interoperability, or the server's actual enforcement. Pre-TLS SIZE evidence is not reused as post-TLS evidence. If STARTTLS or the second EHLO fails, post-TLS evidence remains absent. No policy or Milter disposition changes occur.

Regression coverage: 17 table-driven SIZE parser scenarios and one independent AUTH/STARTTLS behavior check. These are not live Postfix delivery tests. Exact-commit CI and the isolated Postfix/Dovecot laboratory must be inspected separately before claiming a pass. Real mail-host acceptance, SMTP transaction-level SIZE enforcement, tenant policies, classifier false positives, delivery durability, browser UI, backup/restore and native rollback remain outstanding. The October 31 beta target has passed; this change does not qualify a beta.
