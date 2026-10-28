# Understanding authentication scores and Postfix delivery

SpamGate checks SPF using the **SMTP Milter client IP** and the **envelope sender** domain, not a Received header pasted from a different copy of the message. DKIM verification uses the message headers and body and a public key looked up in DNS; a visible DKIM-Signature header is not a cryptographic pass. DMARC alignment depends on verified SPF and/or DKIM, so the DMARC penalty is *not independent evidence of a separate third problem*.

To compare a message with what SpamGate observed, use the same **Message-ID** and scan timestamp. A repeated tracking number, subject or shipment reference is not an unambiguous email identity. Postfix and SpamGate may have seen different messages within the same campaign.

The source of this release's findings is stored per message: DNS SPF domain/IP, DKIM DNS selector/domain, DMARC policy, internal signals, enabled DNSBL zones, and locally trained classifiers. Disabled DNSBL zones and local models that have not been trained contribute nothing.

## Milter decisions are requests, not delivery receipts

Milter `quarantine` requests Postfix's **hold queue**, not Dovecot's Junk folder. A Milter `tag` decision requests `X-Spam: Yes`; SpamGate does not automatically rewrite subjects or configure Dovecot Sieve. Previous versions saved `action=quarantine` without an MTA-action field, so historical empty `delivery` fields must remain **unknown**.

New messages record `mta_action`, e.g. `postfix_hold_requested`, `spam_header_requested`, `smtp_reject_requested` or `continue_requested`. These values deliberately **do not claim successful downstream enforcement**; check Postfix's hold queue and logs for definitive outcomes.

Read-only checks (run directly on the Postfix host):

```sh
postconf -n | grep -E '^(smtpd_milters|non_smtpd_milters|milter_protocol|milter_default_action) ='
sudo postqueue -p
sudo grep -F '<exact-Message-ID>' /var/log/mail.log
sudo grep -F '<Postfix-queue-ID>' /var/log/mail.log
```

Replace placeholders with the full identifier for the *same* message. Do not adjust scoring thresholds or permanently allow a purported FedEx address based only on display-name/domain appearance; sender identities can be forged.

`0.4.0-alpha.9` is a development test build, not a production-qualified replacement for Rspamd.
