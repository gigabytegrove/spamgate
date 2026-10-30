# Native SMTP relay transaction deadlines — 2026-10-30

## Defect

The outbound native relay used `net.Dialer.DialContext` but then set a
fixed 40-second socket deadline, even when the caller supplied a shorter
context deadline or cancelled the operation. `net/smtp` has no context
argument for EHLO, MAIL, RCPT or DATA. A stalled upstream peer could hold
the single delivery worker after cancellation, increasing queue latency and
delaying shutdown.

## Correction

After a successful TCP dial, SpamGate now sets the socket deadline to the
earlier of the caller's deadline and 40 seconds. A `context.AfterFunc`
callback expires the underlying connection's deadline immediately when
the context is cancelled, including during SMTP greeting, TLS negotiation,
AUTH, RCPT and DATA. The underlying TCP connection is captured before
wrapping it in TLS, avoiding a callback race with reassignment.

The existing 40-second upper bound remains for callers with no shorter
deadline. This change does not add an automatic retry outside the durable
queue, does not acknowledge SMTP acceptance before persistence, and does
not change `milter_default_action` or Postfix configuration.

## Regression evidence to collect

- Real TCP test: server accepts a connection and never sends its 220
  greeting; a 180 ms caller deadline must terminate the send promptly.
- Real TCP test: server acknowledges MAIL but stalls RCPT; explicit
  context cancellation must terminate the transaction promptly without
  sending DATA.
- `go test -race -count=1 ./...` and `go vet ./...` at exact commit.
- Isolated Postfix/Dovecot workflow at exact commit.

## Limits

Context cancellation can occur after an upstream SMTP server has accepted
DATA. That is inherently an ambiguous at-least-once delivery window; the
durable queue preserves the original for investigation and possible retry.
These tests do not prove exactly-once delivery, real mail-host behavior,
or production beta qualification. Issue #2 remains open.
