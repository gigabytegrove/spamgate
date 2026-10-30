# Native SMTP relay failure disposition — 2026-10-30

## Scope and invariant

SpamGate remains a native Linux service. The permanent foreground launcher is
`/opt/spamgate/spamgate`; the worker is `spamgate-worker`, persistent state is
`/opt/spamgate/data`, and the Milter interface uses 38470/38472. Nothing in
this change alters Postfix `milter_default_action = accept`, deploys a
container, or modifies a live mail host.

## Failure classification

The outbound SMTP relay now preserves typed transaction-stage errors:

| SMTP phase | Response | Queue behavior |
| --- | --- | --- |
| MAIL, RCPT, DATA | 5xx via `net/textproto.Error` | Mark `dead` after one attempt; preserve original |
| MAIL, RCPT, DATA | 4xx | Remain `queued`; exponential retry |
| MAIL, RCPT, DATA | network failure or unknown error | Remain `queued`; exponential retry |
| Authentication, greeting, STARTTLS, dial | Any failure | Retryable; no automatic permanent-message conclusion |
| SMTP success | DATA accepted | Persist `delivered`, finalize journal, remove spool |

The queue never guesses a status code by parsing free-form SMTP response text.
A definitive 5xx in MAIL/RCPT/DATA indicates that the attempted message
was refused by the upstream. No SMTP DATA acceptance is claimed.

Dead messages retain their original RFC 5322 bytes and immutable envelope in
the durable queue, and receive a `QUEUE_DELIVERY_DEAD` history finding.
Operator Retry remains available after fixing an upstream policy problem.
The history mirror can fail independently; the spool remains authoritative.

## Qualification

Automated coverage:
- Typed 4xx/5xx stage classification, nested errors, network and auth cases.
- Actual TCP SMTP client/server exchanges for RCPT 451/550, DATA 554,
  and successful DATA 250.
- Queue state transitions, durable original retention, suppression of
  automatic dead-letter replay, operator-triggered retry, and retry backoff.

Required before long-term beta:
- Verify behavior against a real upstream Postfix relay with 4xx/5xx policies.
- Verify actual Dovecot delivery, Postfix holds, and queue-ID correlation.
- Validate production-host authentication, TLS certificates, and response
  mapping; a local fake SMTP server is not an interoperability certificate.
- Run power-loss/disk-full and update/rollback drills.
- Audit classifier false positives and tenant policy precedence.

Known limitation: SMTP delivery is **at least once**, not exactly once. If an
upstream returns 250 after DATA and the worker crashes before recording
`delivered`, a retry can duplicate mail. This change does not eliminate
that ambiguity or generate DSNs for dead-lettered messages. Operators must
review dead-letter records; do not claim remote delivery for them.
