# SMTP response framing boundary — 2026-11-23

Scope: native SMTP response serialization only; no mail-host configuration or deployment.

Before this change, smtpWriteResponse accepted arbitrary response strings. Any future dynamic response text containing CRLF could introduce a second SMTP status line or an SMTP command-looking line. The response writer now validates the complete frame before touching a socket. Single-line replies require a three-digit 2xx–5xx code and a space separator. Multiline replies require identical codes, hyphens on continuation lines, a final space separator, printable ASCII, CRLF framing, and bounded length (16 KiB total, 100 lines, 1000 bytes per line). Malformed replies return an error with zero bytes written. This is a defense-in-depth boundary, not proof of SMTP interoperability.

Files: internal/transport/smtp_response_write.go, internal/transport/smtp_response_frame.go, internal/transport/smtp_response_frame_test.go.

Qualification: source changes committed; unit tests NOT EXECUTED; complete Go suite NOT EXECUTED; owner-controlled builder NOT EXECUTED; real Postfix/Dovecot NOT EXECUTED. The available local environment cannot resolve github.com and is not the designated build host. No GitHub Actions were used.

Remaining: issues #1–#9 remain open, especially crash-safe queue replay, actual Postfix/Dovecot final disposition, authentication interoperability, classifier false-positive corpus, tenant isolation, diagnostics, complete browser acceptance, backup/restore, and native update/rollback. Do not infer beta qualification from this change.
