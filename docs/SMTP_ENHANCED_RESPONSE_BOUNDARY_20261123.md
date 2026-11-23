# SMTP enhanced reply framing — 2026-11-23

Source-only engineering change. SMTP replies are validated before socket writes.
The validator now rejects mismatched enhanced-status classes (for example,
250 with 5.7.1), malformed enhanced-status triples, and lines exceeding the
RFC 5321 512-octet maximum including CRLF. Existing multi-line reply-code
and separator checks remain.

Tests are committed but have NOT EXECUTED on the owner-controlled builder.
No production-host qualification, Postfix/Dovecot acceptance, or release
qualification is claimed. The October 31 beta target has passed. All
production acceptance issues #1–#9 remain open.

No GitHub Actions were used. No live mail server was modified.
