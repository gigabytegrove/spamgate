# Disposable native HTTP-to-Postfix HOLD helper integration — 2026-11-01

Scope: production gates #1, #6 and #9. The isolated GitHub Actions Postfix/Dovecot job now exercises a **real authenticated administrator HTTP request** through the SpamGate server handler and the narrow root-owned release helper, running the test executable as the unprivileged spamgate worker.

## Disposable-host sequence

1. Require CI=true, GITHUB_ACTIONS=true, SPAMGATE_DISPOSABLE_POSTFIX_HTTP_LAB=1 and the unprivileged spamgate OS account; refuse all other environments.
2. Start a real SpamGate Milter on 127.0.0.1:38472 with a deterministic harmless quarantine rule. Submit a harmless SMTP message through local Postfix.
3. Observe the real held queue entry with unprivileged postqueue -j and correlate it to a persisted Milter scan using the complete envelope and arrival timestamp.
4. Fetch GET /api/v1/postfix/hold-queue with an administrator session and require the exact scan ID. Reject a POST without CSRF, then POST the exact queue ID, confirmation and reason with CSRF.
5. Require HTTP 202, durable release_submitted audit, one actual native helper invocation (via the real non-root command path), refusal of duplicate POST, and removal from the Postfix HOLD queue.
6. Independently flush the disposable Postfix queue and require exactly one matching Dovecot LMTP INBOX Message-ID, exactly +1 INBOX and no Junk change. Preserve logs in the exact-commit integration artifact.

## Explicit limitations

This is **disposable-host evidence only**, not a production ISPConfig qualification. The test uses a controlled local sender, one recipient and a synthetic admin session; it does not establish browser automation in Chrome/Firefox/Edge, production MTA persistence, tenant ownership for multiple recipients, crash-injected durable recovery, or long-term soak. A successful release HTTP response is explicitly not treated as final mailbox delivery until the independent Dovecot receipt check passes.

Preserve /opt/spamgate/spamgate as permanent foreground launcher, spamgate-worker, persistent /opt/spamgate/data, Milter ports 38470/38472, no Docker substitution, and no automatic modification of the running production mail server. October 31 beta deadline was missed; continue until every production gate is qualified.
