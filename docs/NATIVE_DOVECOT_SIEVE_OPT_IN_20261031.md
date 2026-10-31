# Native Dovecot LDA Junk Sieve opt-in (2026-10-31)

This is an optional explicit native Linux configuration tool for issues #9 and #1. It does not modify the running mail server, reload Dovecot, change Postfix, create mailboxes, or enable SpamGate filtering automatically.

## Preconditions

Confirm that the actual delivery transport is Dovecot LDA, not LMTP or direct Postfix Maildir. Confirm Dovecot Sieve and sievec are installed, the destination Junk mailbox exists, and the trusted Milter strips forged inbound X-SpamGate-* headers before adding its own. Review all existing sieve_before rules. ISPConfig, cPanel, Plesk, and DirectAdmin hosts must use their panel-supported persistent configuration workflow; this tool refuses them.

## Manual opt-in

From a trusted checkout with scripts/fixtures/spamgate-junk.sieve:

    bash scripts/install-dovecot-sieve.sh --preview
    sudo bash scripts/install-dovecot-sieve.sh --apply --confirm DOVECOT-SIEVE
    sudo doveconf -n

The installer creates only /etc/dovecot/sieve/spamgate-junk.sieve, its compiled .svbin, /etc/dovecot/conf.d/99-spamgate-junk.conf, and a checksum manifest. It validates doveconf -n after staging and attempts to roll back its own files on failure. It refuses existing destination files.

After independent review and a maintenance window, an operator may manually restart Dovecot and send controlled tagged and untagged messages. Confirm exact doveadm mailbox placement and Postfix queue-ID correlation. Compilation alone is not acceptance.

## Manual rollback

Only if all four installed files are unchanged:

    sudo bash scripts/install-dovecot-sieve.sh --remove --confirm REMOVE-DOVECOT-SIEVE
    sudo doveconf -n

Review and restart Dovecot manually after rollback. The tool refuses removal when files drift or a symlink appears. A crash during multi-file publication or removal is not transactionally recoverable; inspect the configuration before restarting. SPAMGATE_SIEVE_TEST_* variables are strictly for hermetic tests and must never be used on a production host.

## Evidence and limitations

Hermetic tests exercise read-only preview, missing confirmation, existing-rule conflict, compiler failure, post-install doveconf failure rollback, installation, overwrite refusal, drift-safe removal, and symlink refusal. Real Dovecot/ISPConfig/LMTP host behavior is not proven. Issues #1-#9 remain open pending independent end-to-end acceptance.
