# Postfix release result preflight (2026-11-10)

Issue #1/#9: the native Linux `spamgate-postfix-release` helper performs a privileged `postsuper -H` action. Its output sink must be present **before** invoking Postfix, not checked after the irreversible action. The command now rejects a nil sink before launching the subprocess. Successful command output also requires a complete write; a sink returning a short count and no error is reported as `io.ErrShortWrite`.

## Verification boundaries

`go test ./cmd/spamgate-postfix-release` covers the nil-sink side-effect guard and silent short-write reporting. These are source-level regression cases and must be run in CI before acceptance. The helper cannot make result reporting transactional with the Postfix queue operation: if the sink fails after a successful `postsuper -H`, the queue may already have changed. Operators must inspect queue state and correlated message history rather than retrying blindly. No production mail server or ISPConfig configuration is modified by these changes.

Still required: real correlated HOLD release with queue ID reuse and cross-recipient adversarial tests; actual Dovecot final mailbox placement; ISPConfig persistence; full Postfix/Dovecot integration, UI and authentication regression; and native deployment/rollback qualification. Preserve `/opt/spamgate/spamgate`, `spamgate-worker`, `/opt/spamgate/data`, and Milter ports 38470/38472.
