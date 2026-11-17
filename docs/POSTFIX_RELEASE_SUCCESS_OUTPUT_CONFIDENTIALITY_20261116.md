# Postfix HOLD release: success-path confidentiality

Date: 2026-11-16. Scope: native Linux `spamgate-postfix-release` helper, not a mail-host deployment.

## Finding and change

The earlier failure-path redaction still returned sanitized child stdout and stderr after a successful `postsuper -H`. Sanitization strips terminal controls, not private recipient addresses, queue IDs or spool paths. The helper now returns a fixed success confirmation and never forwards child output on either outcome. Bounded collection, subprocess cancellation, root validation and queue-ID validation remain in place. This is a confidentiality fix; it does not prove that a particular queue item was safely released.

## Regression coverage

`cmd/spamgate-postfix-release/output_confidentiality_test.go` now asserts the fixed success response and tests a successful subprocess emitting sensitive text on both stdout and stderr. Existing failure-path tests continue to require no sensitive output. Tests require Linux; no live Postfix command is executed by these tests.

## Qualification still required

Run exact-HEAD Go tests and engineering CI, verify queue ownership and ID reuse protection, exercise genuine Postfix HOLD/release and Dovecot disposition on an authorized disposable mail host, and record before/after queue evidence. Do not change a running mail server automatically. This change does not close issues #1–#9 or qualify the long-term beta.
