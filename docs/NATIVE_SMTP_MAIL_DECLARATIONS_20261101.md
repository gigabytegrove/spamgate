# SMTP MAIL declaration enforcement — 2026-11-01

## Defect and impact

The native SMTP content-filter listener parsed `MAIL FROM ... SIZE=n` and
`BODY=7BIT/8BITMIME` but discarded both declarations before DATA. A peer
could send a larger original than its declared SIZE, or 8-bit octets without
requesting 8BITMIME. The listener also accepted UTF-8 envelope mailboxes while
its EHLO response did not advertise SMTPUTF8. This could turn a protocol error
into a durably accepted message that the next hop could not relay.

## Implemented contract

- The accepted MAIL transaction retains its declared SIZE and BODY mode.
- The default BODY mode is 7BIT; 8-bit DATA requires BODY=8BITMIME.
- After SMTP dot unstuffing, before scanner/queue/relay, DATA larger than the
  declared SIZE receives 552; undeclared 8-bit DATA receives 554.
- Both errors clear the transaction. The next RCPT or DATA requires a new MAIL.
- Non-ASCII MAIL FROM and RCPT TO paths receive 501 because SMTPUTF8 is not
  advertised. Null reverse paths and valid ASCII addresses remain supported.
- No silent MIME recoding, envelope rewriting, automatic Postfix configuration
  change, or production service restart is introduced.

## Verification scope

Local isolated parser tests were run against equivalent helper code using
Go 1.23.2; repository CI must independently establish integration and race
coverage on its pinned Go toolchain. New repository regressions exercise the
parser, DATA contracts, and a real loopback SMTP exchange without an attached
scanner or durable queue. These are not production Postfix/Dovecot results.

The native architecture remains /opt/spamgate/spamgate as foreground launcher,
spamgate-worker as worker, /opt/spamgate/data as persistent state, and Milter
ports 38470/38472. No Docker substitution.

## Remaining acceptance gates

Issue #3 still requires independent third-party SMTPUTF8, 8BITMIME, SIZE,
STARTTLS, AUTH, SPF/DKIM/DMARC/ARC and Milter conformance evidence. A native
relay may still be unable to deliver mail to an incompatible next hop. Issues
#1–#9 remain open until real mail-host, durability, classifier, tenant, UI,
diagnostic and backup/update/rollback gates are independently qualified.
