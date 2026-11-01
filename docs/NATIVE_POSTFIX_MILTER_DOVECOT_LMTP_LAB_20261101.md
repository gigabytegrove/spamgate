# Real Postfix -> Milter -> Dovecot LMTP disposable qualification (2026-11-01)

This gate extends the existing disposable Ubuntu 24.04 lab. After the independent Postfix/Milter/LDA tests and direct Dovecot LMTP tests, the workflow configures **only its disposable runner** to route local mail through Dovecot LMTP. It reruns the real Postfix/Milter integration suite against the LMTP path, covering SMTP accept, null sender, real Postfix hold/release, SpamGate Milter tag to Junk, forged SpamGate header stripping, 5xx SGTUBE reject and 4xx audit-store tempfail.

## Evidence boundary

Dovecot exposes a dedicated Unix listener at /var/spool/postfix/private/dovecot-lmtp, owned by postfix and mode 0600. Postfix mailbox_transport must equal lmtp:unix:private/dovecot-lmtp. The legacy mailbox_command is set to /bin/false in the **disposable runner** so a successful delivery cannot be attributed to LDA fallback. The existing Milter endpoint 127.0.0.1:38472 and tempfail policy are mandatory. Both services are restarted/reloaded only on the disposable runner.

The new Python evidence collector requires CI=true, GITHUB_ACTIONS=true, SPAMGATE_DISPOSABLE_POSTFIX_LMTP_LAB=1 and --confirm DISPOSABLE-POSTFIX-LMTP-QUALIFICATION. It refuses missing or unsafe sockets and unexpected Postfix routing. Before/after mailbox inventories come from real doveadm queries. Their per-mailbox UID fingerprints are SHA-256 hashes; evidence does not expose mailbox contents or addresses. Verification requires all original messages preserved, exactly four additional INBOX messages and one additional Junk message. It rejects malformed, duplicated, missing, excessive or removed mailbox evidence. It never submits mail or changes Postfix itself.

## Remaining limitations

This is **real SMTP -> Postfix -> SpamGate Milter -> Postfix LMTP transport -> Dovecot Sieve -> Maildir** on a disposable CI VM, not a production host. The test does not prove ISPConfig configuration persistence, production queue permissions, real user/tenant isolation, independent authentication interoperability, disk-full or crash recovery, or production update/restore. The October 31 deadline was missed; issues #1-#9 remain open. No Docker substitution, production mail-server configuration change, or production restart is permitted.
