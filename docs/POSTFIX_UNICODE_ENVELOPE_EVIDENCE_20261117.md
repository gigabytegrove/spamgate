# Postfix queue evidence: Unicode identity safety (2026-11-17)

The read-only inventory and privileged HOLD release authorization use the shared `validPostfixEnvelopeEvidence` validator. The validator now rejects malformed UTF-8, ASCII and Unicode control characters, Unicode format characters (including bidirectional overrides and zero-width formatting), and Unicode line/paragraph separators. Valid UTF-8 SMTPUTF8 envelope identities remain permitted; no ASCII-only policy is introduced. Null reverse paths remain permitted only for senders.

This is evidence hardening, **not** full RFC 6531 mailbox syntax verification or proof of Postfix queue ownership. Queue identity, recipient completeness, and release-attempt persistence are separate checks. A rejected envelope must fail closed rather than automatically change the mail server.

Regression coverage exercises both sender and recipient paths, including legitimate internationalized identities and adversarial formatting. Real mail-host acceptance must verify Postfix `postqueue -j` output, Dovecot placement, HOLD/release reconciliation, restart durability, and safe recovery from indeterminate releases. No production host was modified in this change.

Locked deployment architecture: native `/opt/spamgate/spamgate` foreground launcher, `spamgate-worker`, persistent `/opt/spamgate/data`, Milter ports 38470/38472. No Docker substitution or automatic mail-server configuration mutation.
