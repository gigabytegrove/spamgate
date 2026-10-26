# Postfix after-queue SMTP filter — controlled integration template

**Status:** SpamGate SMTP-to-upstream integration has automated TCP tests, but a live Postfix environment has **not** been qualified. Do not deploy this as a blind configuration patch. Back up `main.cf` and `master.cf` before changing mail flow. Never publish SpamGate's SMTP listener to the public internet.

## Topology and security

The supported alpha flow is `Postfix incoming queue -> SpamGate SMTP :38473 -> Postfix reinjection listener -> delivery queue`. The inbound and reinjection Postfix services **MUST** be separately configured so reinjected messages skip the external content filter. Incorrect configuration causes loops and potentially message loss. See the official [Postfix FILTER_README](https://www.postfix.org/FILTER_README.html) for the authoritative after-queue model.

After-queue rejection requires careful backscatter review: upstream senders may forge envelope addresses. For prequeue reject semantics use a **qualified Milter** integration, not an untested after-queue change.

Do not deploy direct-to-MX forwarding yet. SpamGate only accepts a limited SMTP command subset and does not implement DSN/SMTPUTF8/BDAT/LMTP. All recipient domains and trusted MTA networks must be explicit.

## SpamGate environment (example, not an executable auto-configurator)

For a SpamGate host at `192.0.2.20`, a Postfix server at `192.0.2.10` and a dedicated reinjection service at `192.0.2.10:10026`:

```ini
SPAMGATE_SMTP_LISTEN=192.0.2.20:38473
SPAMGATE_SMTP_TRUSTED_CIDRS=192.0.2.10/32
SPAMGATE_ALLOWED_RECIPIENT_DOMAINS=example.org
SPAMGATE_RELAY_ADDRESS=192.0.2.10:10026
SPAMGATE_RELAY_TLS=required
SPAMGATE_DURABLE_QUEUE=true
```

Replace documentation-only IP addresses and domain names. `SPAMGATE_RELAY_TLS=required` needs a correctly named, trusted STARTTLS certificate; if the upstream certificate does not cover its IP address, use a DNS hostname that resolves on the SpamGate host. Do not switch to plaintext over an untrusted network to suppress TLS errors. Never point `SPAMGATE_RELAY_ADDRESS` back to SpamGate port 38473.

## Dedicated Postfix configuration

An authorized Postfix administrator should adapt the example in Postfix `FILTER_README`, using `scan:<spamgate-ip>:38473` as the delivery transport and a dedicated reinjection SMTP listener. Example **illustration only** for a co-located setup; the host addresses, access controls, receiving overrides, and TLS certificates must be reviewed:

```text
# main.cf — example after-queue content filter
content_filter = scan:[192.0.2.20]:38473
receive_override_options = no_address_mappings
```

```text
# master.cf — FILTER_README principles; adapt to the actual environment
scan      unix  -       -       n       -       10      smtp
  -o smtp_send_xforward_command=yes

192.0.2.10:10026 inet n - n - - smtpd
  -o content_filter=
  -o receive_override_options=no_unknown_recipient_checks,no_header_body_checks,no_milters
  -o smtpd_recipient_restrictions=permit_mynetworks,reject
  -o mynetworks=192.0.2.20/32
```

**Important:** Do not apply these snippets unchanged. The filter route may require a named transport/service format specific to your installed Postfix version. The `scan:` destination in the example must be checked against the actual `master.cf` transport and TLS policy. A live Postfix qualification has not occurred, so **this is not a certified recipe**.

## Acceptance test before touching production traffic

1. Capture the current Postfix configuration using `postconf -n`, `postconf -M` and a versioned backup. Rehearse rollback before continuing.
2. Confirm SpamGate Web UI, first-run setup and the API `/api/v1/runtime` show the intended service configuration; separately confirm the listener is actually bound.
3. Keep inbound Postfix's original queue active while canary routing test messages. Verify STARTTLS, recipient acceptance, envelope preservation, and exact originating client IP provenance.
4. Test clean mail acceptance, tag header insertion, spam hold, reject behavior, bad MIME, 10 MiB boundary, multi-recipient envelopes, transient upstream outage and restarted-delivery recovery.
5. Validate `GET /api/v1/delivery-queue` and the Web UI Delivery queue. Inspect and resolve dead-letter entries. A durable queued `250` means SpamGate now owns delivery responsibility.
6. Check successful delivery shows `relayed`, not merely `queued`, and that quarantine release cannot silently duplicate delivery.
7. Rollback: disable `content_filter` using reviewed Postfix commands; verify reinjection filtering is not recursive. Do not delete a SpamGate spool containing accepted undelivered mail.

**Delivery guarantee:** The single-node outbox is at-least-once. If SpamGate crashes after an upstream SMTP `250` but before its local completion record, delivery may repeat. Exactly-once delivery, DSN notifications, live Postfix version qualification and HA replication remain unimplemented.
