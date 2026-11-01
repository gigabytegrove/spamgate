# Native SMTP DATA wire integrity — 2026-11-01

## Defect and impact

The native SMTP content-filter listener previously accepted LF-only DATA
terminators, removed the first dot from any dot-prefixed line (including
unescaped lines), and allowed DATA lines as long as 16 KiB. These differ from
RFC 5321 DATA framing and from the downstream Go SMTP relay's line contract.
An invalid original could be scanned and durably acknowledged with SMTP 250,
then become an undeliverable dead-letter or have its contents silently changed.

The command reader also accepted bare LF, control octets and lines up to
4096 bytes. That made malformed command/data boundaries ambiguous.

## Implemented

- SMTP commands require CRLF, have a 512-octet wire limit, and reject NUL,
  bare CR and control characters. Invalid framing returns 500 and closes.
- DATA requires CRLF and at most 1000 octets per wire line, including CRLF
  and the transparency dot. Only an exact `.<CRLF>` ends the message.
- Dot transparency removes exactly one dot from valid `..` lines. A
  nonterminating `.` prefix without a second dot is malformed.
- Bare CR, NUL, LF-only DATA and overlong lines return 554 and close the
  connection. Closing is intentional: the remaining stream cannot safely
  be reinterpreted as SMTP commands.
- Oversized but correctly framed DATA is drained to the terminator and
  rejected with 552. The envelope is reset, allowing a new transaction.
- The original and any SpamGate-generated tag headers are checked against
  downstream relay wire limits before durable queue acceptance.
- The existing MAIL SIZE, BODY=8BITMIME, SMTPUTF8 and recipient policy
  checks remain enforced before scanning or SMTP 250.
- HELO, EHLO and RSET clear the retained MAIL parameter state.

## Evidence

The bounded framing helper was exercised locally using a standalone Go
1.23-compatible harness: `go test -race -count=1 ./...` and `go vet ./...`
passed. Repository regressions additionally exercise a real loopback SMTP
exchange, malformed DATA refusal without a scanner or queue, dot-stuffed
delivery through the durable queue, and oversize drain/reuse. The full
repository CI and isolated Postfix/Dovecot workflows must be inspected at
the exact commit before claiming integrated qualification.

## Remaining limitations

This is not a full third-party SMTP interoperability matrix. Real Postfix
content-filter behavior, LMTP and ISPConfig persistence, crash-injected
durability, live Milter disposition, DNS/authentication interoperability,
classifier precision, tenant enforcement, UI, backup and rollback remain
open under issues #1–#9. Do not promote a long-term beta based on these tests.

The native launcher `/opt/spamgate/spamgate`, `spamgate-worker`,
`/opt/spamgate/data` and Milter ports 38470/38472 are unchanged. No
production mail server is modified or restarted.
