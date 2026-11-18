# SMTP greeting compilation and protocol regression — 2026-11-18

Starting main: `d56e038f25cc581077b2f809b4e12cf53cc6a8a6`.

## Defect

The stage latency change concatenated a function call and `if` on one line without a semicolon or newline. Go cannot parse this statement, so the entire native build and engineering CI are blocked. The greeting stage now uses separate statements for timing, error handling and response-code assignment.

## Coverage

Added a loopback TCP test that sends a delayed SMTP 421 greeting and checks typed rejection, stage, classification, elapsed-time evidence and absence of unattempted-stage measurements. Added malformed framing regressions for LF-only, mixed multiline status codes, control bytes, overlong replies and incomplete multiline replies.

## Qualification boundaries

This change does not modify Postfix, Dovecot, systemd, the native launcher, the persistent data directory or Milter listeners. Repository-wide tests and final-HEAD CI must pass before this correction is accepted. Real-host disposition, durable delivery, authentication, classifier false-positive gates, tenant isolation, complete UI, cold restore and native rollback remain open. The 2026-10-31 beta target has passed; this is not beta qualification.
