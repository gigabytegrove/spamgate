# Native SpamGate filtration corpus qualification — 2026-10-31

## Scope and evidence boundary

This tool is a **controlled, opt-in native-host test harness**, not a production installer or automatic mail-server reconfiguration. It does not modify `/opt/spamgate/spamgate`, `/opt/spamgate/spamgate-worker`, `/opt/spamgate/data`, Postfix, Dovecot, or Milter ports 38470/38472. It sends only when explicitly invoked with the `send` subcommand.

It addresses two previously unverified failure modes:
1. **Inflated classifier confidence** from repeated corpus examples. `spamgate-eval --require-unique-ids` rejects duplicate SHA-256 message identities, including duplicates crossing cohorts. The legacy evaluator format remains readable, but strict qualification must use the new flag.
2. **False success from unobserved mail**. `reconcile` refuses to produce evaluator labels unless every SMTP-accepted message has an independently recorded SpamGate verdict. A successful SMTP 250 response is never silently interpreted as a classifier accept or mailbox delivery.

The runner limits each session to 1,000 fixtures, each no more than 128 KiB, a single confirmed recipient, one SMTP session, and at least 250 ms between submissions. It uses IP-literal SMTP targets to prevent DNS rebinding, requires explicit `--allow-remote` for non-loopback addresses, and refuses to overwrite reports. Each attempt is fsynced to a private JSONL journal before transmission and each SMTP outcome is fsynced afterward. Crashes or incomplete journals fail reconciliation.

## Prepare an independently labelled corpus

Place `.eml` files and a `manifest.jsonl` in a private directory. The manifest has one line per independent example, with only `case_id`, `label`, `cohort`, and relative `file`. Example:

```jsonl
{"case_id":"legitimate-001","label":"ham","cohort":"direct","file":"ham/legitimate-001.eml"}
{"case_id":"phishing-001","label":"spam","cohort":"forwarded","file":"spam/phishing-001.eml"}
```

Supported cohorts: `direct`, `forwarded`, `attachment`, `internationalized`, `bulk`, `other`. Labels must be independently adjudicated. **Do not fabricate or relabel test messages after observing SpamGate's decision.** The runner refuses duplicate raw fixture hashes and unsafe paths/symlinks. It replaces recipient routing headers, stale DKIM signatures and untrusted Authentication-Results, and adds a unique correlation header. Consequently, this does not test real DKIM/DMARC or external relay delivery; those require separate live-path qualification.

Validate without sending:

```bash
python3 scripts/spamgate-filtration-qualification.py plan \
  --manifest /root/spamgate-corpus/manifest.jsonl
```

## Controlled local-host submission

**Explicitly approve using your dedicated mailbox first.** The following command transmits the corpus through the localhost SMTP listener. Change the sender to an address your Postfix host permits. The example uses the dedicated test mailbox, not an ordinary user's mailbox.

```bash
umask 077
python3 scripts/spamgate-filtration-qualification.py send \
  --manifest /root/spamgate-corpus/manifest.jsonl \
  --host 127.0.0.1 --port 25 \
  --sender spambox@gigabytegrove.com \
  --recipient spambox@gigabytegrove.com \
  --confirm-recipient spambox@gigabytegrove.com \
  --interval 1 \
  --output /root/spamgate-corpus/submission-20261031.jsonl
```

A remote target requires `--allow-remote` and an IP literal. `--starttls` requires a valid certificate and fails rather than bypassing verification. The output contains no raw email body, only case IDs, SHA-256 fixture digests, run IDs, labels, cohorts, and SMTP transport outcomes.

## Independent observation and strict evaluation

For every `smtp_accepted` event, independently inspect SpamGate's message history, the corresponding Postfix queue/log records, and destination mailbox/Junk/HOLD state. Record the actual SpamGate classifier action, not an inferred action, as one JSONL row per run ID:

```jsonl
{"run_id":"0123456789abcdef0123456789abcdef","action":"accept"}
{"run_id":"abcdef0123456789abcdef0123456789","action":"quarantine"}
```

Allowed actions: `accept`, `tag`, `quarantine`, `reject`, `soft_reject`. The sample IDs above are illustrative and must be replaced with the IDs in the actual report. **No unobserved action defaults to accept.**

```bash
python3 scripts/spamgate-filtration-qualification.py reconcile \
  --report /root/spamgate-corpus/submission-20261031.jsonl \
  --observations /root/spamgate-corpus/observations.jsonl \
  --labels-out /root/spamgate-corpus/labels.jsonl

go run ./cmd/spamgate-eval \
  --require-unique-ids --require-cohorts \
  /root/spamgate-corpus/labels.jsonl
```

The evaluator's default confidence gates require at least 1,000 independently labelled ham and 1,000 spam messages, and two sufficiently populated cohorts, with Wilson 95% confidence bounds. An underpowered corpus fails. Reconciliation still trusts the operator-supplied observation file; it does not independently authenticate those observations against SpamGate or prove downstream delivery.

## Verification and known limitations

```bash
python3 scripts/test-spamgate-host-probe.py -v
python3 scripts/test-spamgate-host-probe-smtp.py -v
python3 scripts/test-spamgate-filtration-qualification.py -v
go test -count=1 ./cmd/spamgate-eval
```

**Critical CI correction:** Earlier `python3 -m unittest discover -p 'test-spamgate-host-probe*.py'` silently reported **0 tests** because hyphenated filenames are not valid Python module identifiers for discovery. The engineering CI and native asset builder now run these files directly. Prior claims of successful host-probe regression based on that discovery command were unsupported.

This work is **not** a 10/10 classifier or beta qualification. It does not automatically obtain actual SpamGate verdicts, establish Postfix queue disposition, test SMTP AUTH or SPF/DKIM/DMARC, measure representative false positives without an independent corpus, simulate power loss, or validate native update/rollback on the real host. Those gates remain open.
