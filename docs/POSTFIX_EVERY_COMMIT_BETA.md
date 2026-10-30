# Postfix/Dovecot regression evidence on every main commit

The isolated Ubuntu GitHub Actions workflow now runs on **every** push to `main`, not only when selected transport files change. Policy, server, diagnostics, and UI changes can regress the mail path. It checks the exact source revision against a real local Postfix Milter and Dovecot INBOX, including accept, synthetic reject, storage tempfail, null reverse-path DSN, Postfix hold/release, and the exact three-message mailbox count.

The workflow preserves a seven-day, SHA-labelled artifact containing Milter test output; Dovecot mailbox counts remain in the workflow log. No original message bodies are archived. Failure in the Go integration test is propagated through `tee` by `set -o pipefail`. The test server and mailbox are ephemeral and cannot alter the user's live mail host.

**Still not qualified:** Dovecot Sieve Junk delivery, actual production-host ISPConfig configuration, cross-tenant hold privilege mediation, authenticated SMTP/TLS against production infrastructure, and live upgrade/rollback. Passing this lab is necessary but insufficient for long-term beta approval.
