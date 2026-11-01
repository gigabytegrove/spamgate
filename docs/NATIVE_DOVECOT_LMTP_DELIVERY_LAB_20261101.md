# Native Dovecot LMTP delivery qualification — 2026-11-01

This change adds **active, disposable-CI-only** Dovecot LMTP delivery verification after the existing real Postfix/Milter/LDA tests. The LMTP phase uses the real Dovecot `dovecot-lmtpd` Unix listener, the installed SpamGate `sieve_before` rule, and independent `doveadm search` queries in both INBOX and Junk.

The five unique Message-ID cases assert clean -> INBOX, trusted tag -> Junk, trusted quarantine -> Junk, action tag without X-SpamGate-ID -> INBOX, and unrecognized reject action -> INBOX. Before sending, both mailboxes must have zero matches for each unique test ID. Afterwards, exactly one mailbox must contain exactly one message. Any wrong-folder, missing, duplicated, unstable, or malformed Dovecot search evidence fails the lab. Evidence is JSON without message IDs, recipient addresses, raw SMTP replies, or mailbox contents.

## Safety boundary

The active test **only** runs with `CI=true`, `GITHUB_ACTIONS=true`, `SPAMGATE_DISPOSABLE_LMTP_LAB=1`, explicit `--confirm DISPOSABLE-DOVECOT-LMTP-DELIVERY`, the fixed `/run/dovecot/lmtp` Unix socket, and the fixed disposable `spamgatebeta@localhost` recipient. Never set these flags on a production server. The lab workflow runs on a GitHub-hosted `ubuntu-24.04` disposable VM, not on any mail server. The normal read-only host probe remains unchanged. Dovecot configuration is changed and restarted **only** inside the disposable CI VM. There is no native installer change and no production Postfix/Dovecot restart.

## Evidence and limitations

The lab workflow retains `lab-evidence/lmtp-delivery.json` and `lab-evidence/dovecot-lmtp-config-probe.json` alongside existing LDA and Milter evidence. The independent engineering workflow runs hermetic negative and state-machine regressions without delivering mail.

**Not proven:** Postfix-to-LMTP routing, Milter header sanitization, SMTP authentication and protocol interoperability, multi-recipient tenant isolation, production mail-host disposition, ISPConfig persistence, or durable delivery crash recovery. Direct LMTP injection bypasses Postfix/Milter, so its trusted-header test is intentionally not a forged-header acceptance test. The October 31 beta deadline was missed; issues #1-#9 remain open until their independent acceptance criteria pass.
