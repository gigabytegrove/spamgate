# SMTP DATA acceptance boundary — 2026-11-22

## Behavior

The outbound relay now returns success immediately after the SMTP server positively acknowledges the DATA terminator. It closes the SMTP connection through the deferred client close instead of synchronously issuing QUIT and waiting for a response.

This avoids tying a successfully accepted message to an unrelated QUIT response timeout. In particular, a slow or unresponsive QUIT response must not hold a worker slot or make the accepted delivery appear unsuccessful to an upstream retry coordinator.

A negative, missing, or timed-out final DATA response **still fails**; this change does not treat write completion alone as delivery acceptance. SMTP's final 250 confirms relay acceptance, **not** mailbox placement. This does not resolve ambiguous delivery if the connection drops before the final response is received.

## Regression

`internal/transport/relay_data_acceptance_test.go` provides a loopback SMTP server that acknowledges the DATA terminator and deliberately never answers QUIT. The client must return successfully and close promptly. This is a hermetic protocol test, not a live Postfix/Dovecot delivery qualification.

## Qualification and remaining gates

- Source committed to main; CI and test execution must be inspected separately.
- No running mail server was modified.
- Locked native deployment paths and Milter ports remain unchanged.
- Real Postfix/Dovecot hold/release and final disposition, durable failure injection, SMTP interoperability, classifier false positives, tenant enforcement, UI, backups and native update/rollback remain open.
- October 31, 2026 target elapsed without end-to-end beta qualification; no beta-ready claim is made.
