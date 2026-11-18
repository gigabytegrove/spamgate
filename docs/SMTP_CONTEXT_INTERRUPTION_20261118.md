# SMTP probe cancellation evidence — 2026-11-18

## Scope
Issue #6: SMTP diagnostic accuracy. This change preserves the cancellation cause when a blocked SMTP read is interrupted by the probe's context cancellation callback. Previously, closing the socket could cause an EOF or closed-connection error to overwrite the actual context deadline/cancellation, misclassifying the failure as an SMTP greeting or EHLO error.

## Implementation
- `internal/smtpprobe/probe.go`: retain the active probe context for the deferred error classifier. If an I/O error coincides with a canceled probe context, return the context's canonical error. Preserve the protocol stage.
- `internal/smtpprobe/context_interruption_test.go`: loopback tests with a TCP server that accepts but does not send a greeting; assert deadline versus caller cancellation, typed errors, failure stage and classification, and socket cleanup.

## Evidence and limitations
Source committed to `main`. GitHub Actions final-HEAD results must be checked independently; committing tests does not prove they ran. This is a read-only SMTP probe change. No mail submission, AUTH exchange, production Postfix/Dovecot integration, or real-host qualification was performed. Issues #1–#9 remain open. This does not establish beta readiness.

Locked native paths and ports remain unchanged: `/opt/spamgate/spamgate`, `spamgate-worker`, `/opt/spamgate/data`, Milter 38470/38472. No Docker substitution or mail-host changes.
