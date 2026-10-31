# Postfix evidence chronology and queue lifecycle hardening — 2026-10-31

Issues: #1 (Postfix/Dovecot disposition), #6 (diagnostics), #9 (hold/Junk evidence).

## Defect and correction

The previous read-only evidence correlator trusted the operator's supplied
rotated-log ordering and could count a status=sent event occurring **after**
the queue had already been removed. Repeated cleanup and queue-removal records
were not always treated as ambiguous. These conditions could make synthetic
or overlapping evidence appear stronger than warranted.

This change adds:

- Timestamp monotonicity checks across supplied files (oldest first), including
  RFC3164 syslog dates and ISO8601 timestamps. Regressions greater than five
  seconds refuse the entire report (exit 2; no output file).
- Explicit log_chronology output: timestamp coverage, mixed formats,
  yearless Dec/Jan rollover count, tolerated reordering, and a conservative
  chronology_validated flag.
- Fail-closed queue lifecycle checks for repeated cleanup identity, repeated
  queue removal, transport after queue removal, and hold after removal.
  These produce ambiguous_queue_identity (exit 3), never transport success.
- Synthetic regression coverage integrated into the main engineering workflow.

## Running the read-only audit

Use only an authorized qualification report and logs from the intended host:

~~~bash
python3 scripts/spamgate-postfix-evidence.py \
  --report /root/spamgate-qualification/send-report.jsonl \
  --postfix-log /var/log/mail.log.2.gz \
  --postfix-log /var/log/mail.log.1.gz \
  --postfix-log /var/log/mail.log \
  --recipient spambox@gigabytegrove.com \
  --confirm-recipient spambox@gigabytegrove.com \
  --output /root/spamgate-qualification/postfix-transport-20261031.json
~~~

Input files must be explicit and oldest first. Output uses exclusive create,
private mode, fsync, and never overwrites existing evidence. This utility
does not access the network, run Postfix commands, alter queues, restart
services, change Milter configuration, or inspect private message bodies.

Run the regression suite:

~~~bash
python3 scripts/test-spamgate-postfix-evidence.py -v
python3 scripts/test-spamgate-postfix-rotation.py -v
python3 scripts/test-spamgate-postfix-integrity.py -v
~~~

## Evidence boundaries

chronology_validated=true establishes only that supplied, parseable
timestamps were monotonic in this input sequence. It **does not authenticate
the logs**. RFC3164 timestamps have no year or timezone. ISO timestamps without
offsets are compared as UTC; the chronology flag does not prove that this
assumption matches the source clock. Missing timestamps, mixed formats, and
tolerated reordering produce chronology_validated=false.

A transport_sent_not_mailbox_verified state is still **not Dovecot receipt,
INBOX/Junk placement, classifier accuracy, hold/release success, or a
production-ready verdict**. Operator-provided input may be incomplete,
tampered with, or from a different host.

## Remaining cumulative gates

Issues #1–#9 remain open. Real Postfix/Dovecot qualification, per-recipient
multi-recipient safety, hold/release verification, durable delivery fault
injection, SMTP/DKIM/ARC/DMARC interoperability, tenant policy enforcement,
corpus-calibrated false-positive bounds, retained operational diagnostics,
browser end-to-end acceptance, cold backup/restore, and native update/rollback
must still be independently demonstrated.

No running mail server is changed by this commit. The permanent
/opt/spamgate/spamgate launcher, spamgate-worker,
/opt/spamgate/data, and ports 38470/38472 are unchanged.
