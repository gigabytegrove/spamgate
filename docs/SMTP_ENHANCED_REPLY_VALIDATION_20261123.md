# SMTP enhanced reply validation — 2026-11-23

Starting main: 164c792e15ced3f55dfe83f9b7628aba16eda1be.

Changed the native SMTP reply validator to separate enhanced-status parsing from full-frame framing checks. The parser enforces class agreement and three numeric components (each at most three digits). The frame validator continues to reject embedded control bytes, mismatched multiline reply codes, invalid separators, and replies exceeding 512 octets per line including CRLF.

Regression coverage includes valid prose and enhanced replies, malformed enhanced status triples, mismatched classes, multiline code mismatches, embedded LF, and 512/513-octet boundaries.

Qualification: GitHub source writes performed; Go tests NOT EXECUTED; Go vet NOT EXECUTED; owner-controlled Linux builder NOT ACCESSED; Postfix/Dovecot integration NOT EXECUTED. No GitHub Actions used. No production deployment, mail-server changes, or release publication.

This does not close issues #1–#9. Highest remaining gates: durable queue crash/retry/failure injection, actual Postfix/Dovecot hold and disposition, tenant enforcement, classifier false-positive measurements, complete browser acceptance, and native backup/update rollback. Deadline October 31, 2026 has passed; beta readiness is NOT established.
