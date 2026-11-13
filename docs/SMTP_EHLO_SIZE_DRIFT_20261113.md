# SMTP EHLO failure and SIZE drift evidence — 2026-11-13

The read-only SMTP probe now reports `EHLO_NOT_ACCEPTED` when an initial EHLO received a non-250 response, and `POST_TLS_EHLO_NOT_ACCEPTED` when a verified STARTTLS session receives a non-250 response to its second EHLO. No response (`0`) is not mistaken for a server rejection. Post-TLS evidence is never inferred from an unverified handshake.

When both initial and post-TLS EHLO replies succeeded and both advertised numeric SIZE limits, `SIZE_LIMIT_CHANGED_AFTER_TLS` records a difference. It is informational: SMTP extensions can change after STARTTLS, and this does not by itself establish a server defect. These findings use fixed operator-facing strings, not untrusted SMTP peer text.

Tests: `go test ./internal/smtpprobe -count=1` and full repository engineering qualification. The test source covers initial and post-TLS EHLO rejection, missing evidence, unverified TLS, changed limits in either direction, unchanged limits, and unknown limits.

This is protocol observation only. No credentials are submitted, no message is delivered, and no live Postfix/Dovecot or ISPConfig host is qualified. The permanent native launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, data `/opt/spamgate/data`, and Milter ports 38470/38472 remain unchanged. Production issues #1–#9 remain open pending their independent acceptance gates.
