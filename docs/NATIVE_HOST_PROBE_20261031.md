# SpamGate native host probe — October 31, 2026

This is an opt-in test utility, **not** proof that SpamGate is beta-qualified.

## Safe read-only preflight

```bash
python3 scripts/spamgate-host-probe.py --output /root/spamgate-preflight.json
```

No SMTP connection is made in this mode. It reports the expected native launcher, worker and persistent data path without reading private message contents or changing Postfix, Dovecot, or SpamGate.

## One controlled local SMTP delivery

Only use a mailbox under your control. The test target defaults to localhost port 25. The explicit recipient confirmation is intentional.

```bash
python3 scripts/spamgate-host-probe.py --send \
  --recipient spambox@example.org \
  --confirm-recipient spambox@example.org \
  --host 127.0.0.1 --port 25 \
  --output /root/spamgate-smtp-probe.json
```

Replace the example address with your dedicated test mailbox. **Do not run against a production destination until you have approved sending the probe.** For a remote target, additionally pass `--allow-remote`. For STARTTLS with normal certificate verification, pass `--starttls`. A certificate mismatch is a failure, not an excuse to disable verification.

The report contains a unique `run_id`; the message Subject and `X-SpamGate-Probe-ID` include that ID. Correlate it with SpamGate history, Postfix logs and the destination mailbox. SMTP acceptance is not mailbox delivery proof.

## Synthetic category tests

An optional `--category-marker` adds a harmless single-line synthetic marker to the body. Use only a known marker from the authenticated SpamGate category lab and only the dedicated test mailbox. Synthetic matches are **not** evidence of real-world spam detection.

## Qualification still required

- Independently adjudicated ham and spam corpus, including direct and forwarded cohorts, measured with `spamgate-eval`.
- Real mailbox receipt, Junk placement, HOLD release and safe false-positive recovery.
- SMTP authentication and TLS conformance with independent tools.
- Disk-full, crash, restart, repeated delivery and power-loss fault injection.
- Browser end-to-end administration, tenant isolation, cold backup/restore and native update/rollback.
- A test plan and evidence for the running host, which is deliberately not modified by this script.

## Automated regression

```bash
python3 -m unittest discover -s scripts -p 'test-spamgate-host-probe.py' -v
```

The engineering GitHub Actions workflow runs this suite and asserts that the default invocation never attempts SMTP.


## Isolated SMTP wire regression (new)

`scripts/test-spamgate-host-probe-smtp.py` runs a temporary SMTP server bound to `127.0.0.1` with an ephemeral port. It drives the **actual Python probe process** over a socket, testing SMTP acceptance, RCPT refusal, DATA refusal, and explicitly opted-in synthetic marker transport. It verifies the message carries the correlation ID and that SMTP failures are not reported as successes.

Run both safety and SMTP wire regressions:

```bash
python3 scripts/test-spamgate-host-probe.py -v
python3 scripts/test-spamgate-host-probe-smtp.py -v
python3 scripts/test-spamgate-filtration-qualification.py -v
```

This lab deliberately does not invoke Postfix, Dovecot, or the SpamGate classifier. It validates the probe itself before that probe is used for real-host tests. The GitHub engineering workflow now runs both test files.

**Acceptance evidence boundary:** A passing wire regression means the test harness can safely submit and classify SMTP transport outcomes against a fake MTA. It does not establish real spam detection, real mailbox delivery, or native beta readiness.


**Regression correction (October 31):** The earlier `unittest discover` command silently executed **zero** tests because the test filenames contain hyphens. The build and engineering workflow now invoke each script directly and fail on assertion errors. This correction supersedes any earlier claim that the host-probe tests passed merely because discovery returned exit code zero.
