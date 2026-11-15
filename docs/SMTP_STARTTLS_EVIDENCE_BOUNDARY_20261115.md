# STARTTLS advertisement evidence boundary — 2026-11-15

This change distinguishes **absent** STARTTLS from **malformed or duplicated** STARTTLS EHLO extension evidence in the read-only SMTP diagnostic. A server that sends `250-STARTTLS extra` or repeats `250-STARTTLS` now receives a stable parser warning (`MALFORMED_STARTTLS_ADVERTISEMENT` or `DUPLICATE_STARTTLS_EXTENSION`) and the assessment finding `STARTTLS_EVIDENCE_UNTRUSTWORTHY`. It must not receive the categorical `STARTTLS_NOT_ADVERTISED` finding for those observations. A clean EHLO without STARTTLS still receives the missing-extension finding.

The probe does not send credentials or mail. Its existing `RequireTLS` downgrade refusal remains intact. These are protocol-observation diagnostics, **not** evidence of real SMTP AUTH enforcement, certificate policy, successful mail delivery or production-host readiness.

Regression tests: `go test ./internal/smtpprobe` and full project `go test ./...`. Final-HEAD CI and production Postfix/Dovecot acceptance must be verified separately. The October 31 beta target has passed; issues #1–#9 remain open until their own end-to-end acceptance evidence exists.
