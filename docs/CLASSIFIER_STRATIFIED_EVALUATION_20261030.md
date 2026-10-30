# Stratified, independently labelled classifier qualification — 2026-10-30

The native `spamgate-eval` now optionally evaluates privacy-safe mail-path cohorts to detect minority-class false positives hidden by a large global sample. Existing two-field JSONL input and default global statistical gate remain backward compatible. Add the optional `cohort` key with exactly one of `direct`, `forwarded`, `attachment`, `internationalized`, `bulk`, or `other`. These are **mutually exclusive analyst-assigned categories**, not message IDs or inferred ground truth. Unknown keys and arbitrary cohort strings are rejected to avoid leaking tenant identities in reports.

For stronger evidence run:

```sh
./spamgate-eval-linux-amd64 --require-cohorts --min-ham=1000 --min-spam=1000 --max-fpr-upper=0.01 --min-recall-lower=0.90 --min-cohort-ham=100 --min-cohort-spam=100 --max-cohort-fpr-upper=0.05 --min-cohort-recall-lower=0.75 labels.jsonl
```

The optional cohort gate requires **all** records to have a recognized cohort, at least two cohorts, and each cohort to independently pass its minimum ham/spam sample sizes and Wilson 95% false-positive/recall bounds. Exit 0 means both global and cohort gates passed for this corpus, exit 3 means a statistical gate failed, and exit 2 indicates invalid input or flags. Reports contain aggregate counts only and sorted cohort summaries. `soft_reject` remains a positive intervention, including when it delays legitimate mail.

This does not establish sample independence, representative production traffic, balanced class labels, time drift, or actual mailbox disposition. A real, adjudicated corpus and independent live comparison remain necessary before issue #5 can close.
