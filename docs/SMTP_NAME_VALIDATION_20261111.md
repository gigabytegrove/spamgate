# SMTP probe hostname validation — 2026-11-11

Scope: issue #3 (SMTP compliance), issue #6 (read-only diagnostics). The native diagnostic remains an inspection-only client: no MAIL FROM, RCPT TO, DATA, AUTH credentials, queue mutations, or changes to the running mail host.

The EHLO argument is validated before dialing: DNS labels must contain ASCII letters, digits, or internal hyphens, be 1–63 bytes, and be separated by single dots. An optional terminal dot is accepted. SMTP address literals are limited to bracketed IPv4 or bracketed `IPv6:` values parsed by Go's IP parser. Names with control characters, whitespace, underscores, shell/protocol metacharacters, empty labels, or excessive lengths are rejected. TLS certificate verification names accept DNS names or unbracketed IPv4/IPv6 addresses; certificate verification and TLS 1.2 minimum remain enabled.

This is intentionally not an SMTP server conformance suite. No authentication exchange or message delivery is attempted. A valid EHLO name does not prove DNS resolution, forward-confirmed reverse DNS, SPF, DKIM, DMARC, ARC, or tenant delivery policy.

Evidence: source changes to `internal/smtpprobe/names.go` and `probe.go`; regression fixtures in `names_test.go`. Local Git checkout was blocked by inability to resolve github.com; exact-HEAD tests and GitHub Actions must pass before qualification. No production host was accessed.

Remaining acceptance: run full Go regression and race tests; independently inspect exact-HEAD CI; execute a controlled read-only probe against authorized Postfix endpoints; exercise malformed server replies, STARTTLS downgrade refusal, and certificate hostname failures; then perform separate real mail-host end-to-end qualification for issue #3.
