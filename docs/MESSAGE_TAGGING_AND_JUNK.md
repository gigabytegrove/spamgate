# Marking spam versus moving to Junk (Postfix + Dovecot)

SpamGate does not control users' IMAP folders. Postfix invokes the Milter before
accepting a message; Dovecot delivers it. These are separate operations.

When a mail's score reaches the **tag** threshold but is below the quarantine
threshold, SpamGate requests the following Postfix header additions:

```text
X-Spam: Yes
X-Spam-Status: Yes, score=6.00 required=5.00
X-SpamGate-Score: 6.00
X-SpamGate-Action: tag
X-SpamGate-ID: <unique scan ID>
```

The values above are examples, not live measurements. A **quarantine** verdict
asks Postfix to HOLD the message in its hold queue; it does **not** request a
Junk-folder move. A **reject** verdict rejects it during SMTP. SpamGate does not
automatically rewrite Subject because that can invalidate existing DKIM
signatures and makes threading unreliable.

To move **tagged** messages (and quarantine verdicts in Junk-header mode) to Junk when they would otherwise go to INBOX,
configure Dovecot's Sieve mail-delivery rules. For a managed ISPConfig server,
use its supported per-mailbox/global Sieve configuration mechanism: do not
blindly edit generated files. The following is a **snippet** to incorporate
into an existing Sieve script (not a complete replacement):

```sieve
require ["fileinto"];
if allof (header :matches "X-SpamGate-ID" "*",
          header :is "X-SpamGate-Action" ["tag", "quarantine"]) {
  fileinto "Junk";
  stop;
}
```

Confirm the target mailbox has a Junk folder and that Dovecot delivers using
Sieve. Validate the resulting Sieve script with your system's sieve compiler
(e.g. `sievec`) and run a non-production message through the path. Preserve
existing vacation replies and rules. Do not deploy this globally without
checking shared domains, forwarding paths, and user preferences.

For investigation, match `X-SpamGate-ID` to the message inspector, where you can
see the exact weighted findings and policy thresholds. SpamGate records that
headers were **requested** from the Milter and does not claim final delivery.

SpamGate removes inbound `X-SpamGate-*`, `X-Spam` and `X-Spam-Status` verdict headers in Milter mode before adding its own. This needs Milter CHGHDRS support; if unavailable and inbound verdict headers are present, the message is deferred instead of trusting a forged spam label. The Sieve example deliberately checks **SpamGate-specific** headers, not an arbitrary sender-provided `X-Spam: Yes`.

## Disposable real Postfix/Dovecot Sieve qualification

The `postfix-dovecot-lab` GitHub Actions workflow installs Postfix,
Dovecot LDA and Pigeonhole Sieve in an isolated Ubuntu runner. It compiles
`scripts/fixtures/spamgate-junk.sieve`, routes local Postfix delivery
through Dovecot LDA, and tests actual mailbox placement.

The integration test checks one genuine Milter-tagged message in **Junk**,
four accepted messages in **INBOX** (including a forged inbound
`X-SpamGate-Action: tag` that must be stripped), and no delivery for
rejected or temporarily failed messages. The hold is released using the
real Postfix queue command. Counts are confirmed independently with
`doveadm mailbox status` and mailbox-specific `doveadm search`.

This is a disposable-host test, not permission to edit a production
Dovecot or ISPConfig configuration. The fixture is a reference rule:
integrating it into an existing Sieve pipeline requires preserving
existing user rules, folder names, ordering and rollback.
