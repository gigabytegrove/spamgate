# Controller training representation boundary — 2026-11-23

Starting revision: `78679963375723c9528fe36d12ce2ff65b8144d6`.

The optional authenticated Rspamd-compatible controller accepts raw RFC 5322 samples. Its training endpoints now reject form, JSON, multipart, MIME parameters, compressed content encodings and ambiguous duplicate header representations before reading or submitting a sample to Bayes. Existing clients omitting Content-Type remain supported, as do `message/rfc822`, `text/plain` and `application/octet-stream` without parameters. Directly constructed noncanonical header keys are inspected case-insensitively. Request bodies are closed on all early exits, including declared-size rejection.

Security boundary: this is representation validation, not a complete RFC 5322 or classifier-poisoning defense. Multipart and encoded uploads return HTTP 415. Bounded sample size and cancellation handling remain enforced separately. No automatic mail-server configuration changes.

Qualification: Go compilation, full tests, race tests, native Linux packaging and real Postfix/Dovecot acceptance NOT EXECUTED. The available local Go 1.23.2 is below go.mod 1.27.4; direct GitHub checkout is blocked by DNS. GitHub Actions are prohibited and were not invoked. Source and regression cases were committed through the GitHub repository connector, not run. All production issues #1–#9 remain open. No production deployment or release.
