# Postfix rotated log correlation hardening — October 31, 2026

Issue #1 (mail disposition) and issue #6 (operational diagnostics). This change
extends the existing **read-only** Postfix evidence correlator. It does not
alter the native launcher, worker, persistent data, systemd unit, Postfix or
Dovecot configuration, or message queues.

## Running the bounded correlation

Pass logs in chronological order, **oldest first**, including gzip-rotated
archives and the current plaintext log. Paths are explicit; the script does
not glob, invoke journalctl, or open production logs automatically.

```bash
python3 scripts/spamgate-postfix-evidence.py \
  --report /root/spamgate-qualification/send-report.jsonl \
  --postfix-log /var/log/mail.log.2.gz \
  --postfix-log /var/log/mail.log.1.gz \
  --postfix-log /var/log/mail.log \
  --recipient spambox@gigabytegrove.com \
  --confirm-recipient spambox@gigabytegrove.com \
  --output /root/spamgate-qualification/transport-evidence.json
```

The operator must first obtain the qualification report from an authorized
test mailbox. Do not substitute ordinary production traffic for a controlled
qualification corpus. The evidence file is exclusive-create and is never
overwritten. The tool does not send mail.

## Safety and evidence boundaries

- Each log must be a regular file, at most 64 MiB compressed/on disk.
  Expanded content is independently limited to 64 MiB and lines to 64 KiB.
- Symlinks, changed inode identities, malformed gzip headers, corrupt gzip
  trailers, decompression bombs and oversized lines fail the operation.
- gzip data is streamed in memory with bounded reads; no extracted copy is
  written to disk. Concatenated gzip members are supported.
- At most 16 logs are accepted. Supply all relevant rotations in correct
  order; omitted or out-of-order logs can prevent reliable correlation.
- Queue ID reuse is marked ambiguous, not silently accepted as delivery.
- A successful Postfix `status=sent` with queue removal is still **transport
  evidence only**. It is not Dovecot mailbox receipt, Junk placement, or a
  classifier verdict. Independent Maildir evidence is required.

## Verification

```bash
python3 scripts/test-spamgate-log-reader.py -v
python3 scripts/test-spamgate-postfix-rotation.py -v
python3 scripts/test-spamgate-postfix-evidence.py -v
```

The first suite tests real plaintext and gzip files, corruption, concatenated
members, symlinks and compressed expansion limits. The second drives the
actual correlator process across log rotation and refuses corrupt evidence.
The original correlator regressions remain enabled. These are isolated
fixtures, not live mail-host certification.

Outstanding: Postfix journal input, timestamp-order validation, adversarial
multi-recipient queue reuse, production-host log retention and permissions,
live hold/release, mailbox delivery, and end-to-end rollback qualification.
