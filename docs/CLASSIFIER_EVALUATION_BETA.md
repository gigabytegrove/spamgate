# Independent labelled classifier evaluation (issue #5)

`spamgate-eval` is a **native Linux command-line companion**, not a mail listener, a Docker image, or an automatic policy change. The engineering CI builds `dist/spamgate-eval-linux-amd64` alongside the existing permanent launcher and worker.

Create an independently adjudicated JSON Lines corpus with exactly `label` (`ham` or `spam`) and `action` (`accept`, `tag`, `quarantine`, `reject`, `soft_reject`) on each line. The input must come from held-out, representative messages, not from SpamGate's own verdict as the ground truth. No subjects, senders, message bodies, or IDs are required or accepted.

Example (two records, **not enough for qualification**):

```jsonl
{"label":"ham","action":"accept"}
{"label":"spam","action":"reject"}
```

Run `./spamgate-eval-linux-amd64 --min-ham=1000 --min-spam=1000 --max-fpr-upper=0.01 --min-recall-lower=0.90 labels.jsonl`. Exit 0 means this supplied corpus meets the specified statistical thresholds; exit 3 means it fails; exit 2 means invalid input. The JSON report includes confusion matrix, observed false-positive rate, precision, recall, and Wilson 95% confidence bounds. `soft_reject` is conservatively counted as an intervention, including a potential false positive for ham. The CLI streams data with bounded line length and emits only aggregate counts.

**Not a production certification:** No independent labelled production corpus is included. The default minimum of 1,000 ham and 1,000 spam is a screening floor, not proof of representativeness. Review samples across senders, languages, attachments, authenticated and forwarded mail, tenants, and time windows. This evaluator cannot prove mailbox delivery or detect label leakage/selection bias. Preserve immutable scan evidence and compare against Rspamd before enabling irreversible reject actions. Issue #5 remains open.
