# Native Maildir placement evidence (2026-10-31)

## Purpose and evidence chain

This read-only qualifier addresses a missing observation in issues #1, #6, and #9: a Postfix status=sent line is not proof of a message in Dovecot's INBOX or Junk. The new script correlates an independently accepted SMTP corpus run to a recipient-bound Postfix transport report and then to exactly one on-disk Maildir message with the same unique Message-ID.

1. scripts/spamgate-filtration-qualification.py send produces a durable run report after explicit SMTP opt-in.
2. scripts/spamgate-postfix-evidence.py matches cleanup queue IDs, recipient transport and queue removal. Its JSON now includes the recipient, and discard/error transports are never certified as delivery.
3. scripts/spamgate-maildir-evidence.py reads that recipient-bound JSON and searches the explicitly selected INBOX and Junk Maildir new/ and cur/ directories for each unique run_id@spamgate-qualification.invalid Message-ID.
4. The output records inbox, junk, missing, or duplicate for every run. Optional independently specified placement expectations require the correct INBOX/Junk folder per case; no ham/spam folder mapping is assumed. Exit 0 requires exactly one match per run and, if expectations were provided, every folder match; 3 means incomplete, duplicate or misplaced mail; 2 means unsafe or invalid evidence.

**This is not an automatic mail-host test.** No live mailbox was accessed during development. Maildir file placement is not independent proof of Dovecot IMAP visibility, Sieve enforcement, mailbox ownership, or correctness of classifier verdicts. Dovecot mdbox/sdbox/other storage is unsupported; do not infer Maildir paths from a username or assume the example paths match the server.

## Operator workflow (read-only after separate, explicit corpus send)

Verify the actual Dovecot storage backend and mailbox layout first. Export Postfix logs oldest-first. The following is a template showing required arguments; use the real confirmed mailbox paths and evidence files, not invented defaults.

~~~bash
cd /opt/spamgate-source

python3 scripts/spamgate-postfix-evidence.py \
  --report /root/spamgate-corpus/submissions.jsonl \
  --postfix-log /root/spamgate-corpus/postfix-old.log \
  --postfix-log /root/spamgate-corpus/postfix-new.log \
  --recipient spambox@gigabytegrove.com \
  --confirm-recipient spambox@gigabytegrove.com \
  --output /root/spamgate-corpus/postfix-evidence.json

python3 scripts/spamgate-maildir-evidence.py \
  --transport-evidence /root/spamgate-corpus/postfix-evidence.json \
  --inbox-maildir /path/to/confirmed/Maildir \
  --junk-maildir /path/to/confirmed/Maildir/.Junk \
  --recipient spambox@gigabytegrove.com \
  --confirm-recipient spambox@gigabytegrove.com \
  --expected-placement /root/spamgate-corpus/expected-placement.jsonl \
  --output /root/spamgate-corpus/maildir-evidence.json
~~~

The optional expected-placement JSONL contains exactly one record for each case, for example {"case_id":"ham-001","folder":"INBOX"} or {"case_id":"spam-001","folder":"Junk"}. The independently adjudicated expected folder must reflect the configured policy; do not infer Junk from a spam label. Omit --expected-placement to collect placement observations without evaluating policy expectations.

The second command refuses missing or incomplete transport evidence. The first command's status=sent correlation alone cannot certify mailbox placement. Each output is exclusive-create, mode 0600, fsynced, and never overwritten. No mail is sent by either evidence analyzer.

## Bounds and safety

- Transport evidence JSON is bounded to 2 MiB, with no-follow regular-file open.
- At most 1,000 distinct run IDs, case IDs and queue IDs are accepted.
- At most 20,000 entries are inspected across the four Maildir directories. Entries must be regular files; symlinks and unexpected types are refused.
- Each Maildir file must be at most 64 MiB. Headers are bounded to 128 KiB. Only headers are parsed; message bodies are not copied into the evidence report.
- INBOX and Junk must be distinct directories with real new/ and cur/ directories. The scanner never writes to either Maildir.
- Scanning a live Maildir is not an atomic snapshot. Concurrent delivery, expunge or folder moves can produce incomplete/ambiguous evidence. Repeat against a consistent read-only snapshot if necessary, without altering the live mailbox.
- Do not use this tool on mdbox/sdbox, IMAP virtual folders, or paths that are not verified for the intended recipient.

## Executed verification and remaining gates

The new Maildir script and its **22 isolated regression tests** were run locally with Python 3 and all 18 passed after fixing a directory-FD handling defect found during the first run. The tests cover INBOX/Junk/new/cur, missing and duplicate placement, multiple cases, wrong recipient, incomplete or reused queue identity, symlinks, oversized headers, existing output, and missing folders, matching and mismatching independent folder expectations. This is synthetic filesystem evidence only. The existing Postfix analyzer received a recipient-binding and discard/error transport safety fix with two additional regressions; those integration tests and final GitHub Actions results must be verified independently before asserting success.

Open production gates remain: actual Postfix/Dovecot host qualification, Milter HOLD/release, Dovecot Sieve placement and IMAP visibility, durable crash/disk-full recovery, SMTP/authentication conformance, representative classifier false-positive bounds, tenant conflicts, browser accessibility, and native update/rollback. The October 31 morning long-term beta target was not met. Do not close issues #1–#9 based on this isolated tool alone.

Locked native layout remains /opt/spamgate/spamgate launcher, /opt/spamgate/spamgate-worker worker, /opt/spamgate/data persistent, management 38470 and Milter 38472. No Docker substitution, no automated live mail-host changes, and no modification of milter_default_action=accept.
