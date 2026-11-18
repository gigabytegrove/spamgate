# SMTP diagnostic latency evidence — 2026-11-18

Scope: issue #6. Native SMTP probe now emits `probe_duration_ms` for completed success and error outcomes and `tls_handshake_ms` when STARTTLS negotiation reaches the TLS handshake. Both values use monotonic elapsed time, rounded upward to whole milliseconds; they do not expose peer reply text or credentials. A missing handshake measurement means no handshake was attempted, not that a handshake completed instantaneously.

Changed source: `internal/smtpprobe/probe.go`. Regression coverage: `internal/smtpprobe/latency_evidence_test.go` for configuration failure, stalled greeting and successful read-only plaintext EHLO. No AUTH, MAIL FROM, RCPT TO or DATA commands are sent.

Evidence: source and tests committed through GitHub; repository-wide Go tests and final-HEAD Actions qualification not yet verified at documentation time. Prior Actions run 44299844884 reported cancelled; this is not a pass. No production mail host was accessed or changed.

Remaining gates: persistent historical latency distributions, authenticated session evidence, queue trend histories, alerting, real Postfix/Dovecot disposition and HOLD, durable delivery, SMTP/authentication compliance, classifier precision/recall and false positives, tenant enforcement, complete browser workflows, cold recovery and native update/rollback. All issues #1–#9 remain subject to independent acceptance. The October 31 beta target passed without production qualification.

Architecture remains /opt/spamgate/spamgate foreground launcher, spamgate-worker, persistent /opt/spamgate/data and Milter ports 38470/38472; no Docker substitution or automatic mail server changes.
