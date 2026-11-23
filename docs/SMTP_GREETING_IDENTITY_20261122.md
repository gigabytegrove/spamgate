# Native SMTP greeting identity enforcement — 2026-11-22

Scope: issue #3 (SMTP protocol and authentication conformance), with issue #6 diagnostics relevance. This is source hardening, not protocol certification.

## Changed behavior
- EHLO and HELO now validate the complete argument before recording a greeting or resetting transaction state.
- Accepted identities: ASCII DNS-style labels, bracketed IPv4 literals, and bracketed `IPv6:` literals.
- Rejected identities: whitespace/control characters, Unicode lookalikes, malformed DNS labels, malformed address literals, scoped IPv6 literals, and overlong values.
- No DNS lookup or Unicode normalization is performed at greeting time. XFORWARD retains its existing independent trust and validation path.
- The rejection is SMTP 501, and a rejected greeting does not establish a new authenticated or accepted SMTP transaction.

## Regression coverage
`internal/transport/smtp_greeting_identity_test.go` contains table-driven valid/invalid cases and a loopback TCP transaction that checks malformed HELO/EHLO refusal, MAIL-before-valid-HELO refusal, recovery with a valid HELO, RSET, and QUIT. No production host is touched.

## Verification and acceptance limitations
- GitHub source commits were published to main. No owner-controlled builder or full regression execution was available in this pass: **NOT EXECUTED**.
- No GitHub Actions, workflow APIs, status checks, or runner evidence were used.
- Required remaining evidence: isolated native Linux build and complete test suite on the designated owner-controlled builder with immutable SHA and logs; real Postfix XFORWARD/EHLO interoperability; Dovecot disposition; durable delivery failure injection; and all nine production issue acceptance gates.
- No production deployment, live configuration change, or release was attempted.
- October 31, 2026 target has passed. Beta qualification is not established.
