# Native filtration evidence JSON and reconciliation integrity — 2026-11-02

Production gates: [#5](https://github.com/gigabytegrove/spamgate/issues/5) (classifier measurement) and [#6](https://github.com/gigabytegrove/spamgate/issues/6) (diagnostic/evidence reliability).

## Failure mode and correction

The opt-in `scripts/spamgate-filtration-qualification.py` harness formerly used Python's permissive `json.loads` for its corpus manifest, durable SMTP submission report, and independently supplied verdict observations. Duplicate object members (including escaped Unicode aliases) silently selected the last value. Thus a file containing contradictory `label` or `action` fields could be reconciled into a misleading evaluation corpus. Malformed observation types could also trigger an unhandled traceback instead of a clean refusal.

The shared JSONL loader now rejects duplicate members at every object nesting level, escaped aliases, non-finite numeric tokens, non-object records, oversized lines and excessive physical lines. No mail is transmitted in `plan` or `reconcile` modes.

The reconciler now enforces an exact event schema and ordered journal transaction: each `attempted` event must be immediately followed by a matching `smtp_accepted` or `failed` event. Each event must carry a valid case ID, 32-character lowercase hexadecimal run ID, 64-character lowercase SHA-256 fixture digest, independent ham/spam label and one of the six supported privacy-safe cohorts. No duplicate case ID, run ID, or fixture digest may inflate a batch. A terminal event cannot rewrite the original attempt's identity, label or cohort. A failed or incomplete batch never produces a classifier label file.

The observation input requires exactly a valid run ID and an explicit supported action. Invalid JSON or wrong types fail with exit code 2 rather than generating a report. Reconciled labels are still written only after the full journal and observations pass validation, using exclusive, fsynced publication.

## Regression and execution

```bash
python3 scripts/test-spamgate-filtration-qualification.py -v
python3 scripts/spamgate-filtration-qualification.py plan --manifest /private/corpus/manifest.jsonl
python3 scripts/spamgate-filtration-qualification.py reconcile --report /private/corpus/submission.jsonl --observations /private/corpus/observations.jsonl --labels-out /private/corpus/labels.jsonl
```

The existing engineering qualification workflow invokes the full Python regression file directly. New cases include duplicate/Unicode-aliased keys in manifest/report/observations, contradictory terminal events, missing fields, malformed run IDs and hashes, unpaired attempts, non-object events, non-finite numbers, duplicate message digests, excessive blank lines and a valid offline reconciliation control.

## Scope and remaining risks

This is **evidence-format and transaction-integrity enforcement**, not cryptographic attestation. A privileged operator can still fabricate a fully self-consistent report or observations. The harness does not independently verify that an observation came from SpamGate, that a label was adjudicated without knowledge of the verdict, or that Postfix/Dovecot placed the message in a final mailbox. It does not test a representative production corpus or prove any classifier false-positive bound.

Previously accepted ambiguous JSONL files will now be refused. Preserve originals for investigation; do not automatically normalize contradictory evidence. The native launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, data `/opt/spamgate/data` and Milter ports 38470/38472 remain unchanged. No Docker substitution, automatic MTA changes or production restart are involved. The missed October 31 beta target remains unmet pending all nine production gates.
