# Postfix evidence correlation hardening — October 30, 2026

The read-only, admin-authenticated delivery-evidence endpoint now requires a
syslog/journal timestamp and a Postfix process in the actual log prefix.
Attacker-supplied SMTP warnings containing a forged `postfix/smtp` substring
cannot create false delivery events. Only Postfix delivery-agent process lines
may populate the parsed `status` field.

The endpoint reads the active configured log and at most one plain-text
`.1` rotation (4 MiB tail each), preserving chronological file order and
the 100-event response cap. Both paths must be regular non-symlink files,
with identity checked again after open. Compressed and older rotations are
not covered; truncation is explicit where known.

This is still **Postfix log evidence, not proof of mailbox delivery**.
Queue IDs may be reused over time and `status=sent` means accepted by the
next hop. The user must verify actual hold state and Dovecot INBOX/Junk
placement independently. No host configuration or mail queue is changed.
