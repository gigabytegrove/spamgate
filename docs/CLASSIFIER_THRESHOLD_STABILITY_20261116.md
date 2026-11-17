# Offline classifier threshold sensitivity qualification (2026-11-16)

This change addresses part of issue #5 (classifier false-positive and threshold robustness). It is **not** production qualification and does not modify running mail, Milter decisions, Postfix, Dovecot, tenant policies, or the locked native Linux installation.

## Operator usage

Run with a validated labeled JSON corpus on standard input:

```sh
spamgate-classifier-eval -threshold=5 -stability-margin=0.5 -max-stability-flips=0.05 < corpus.json > report.json
```

The optional `-stability-margin` generates a `stability_audit` for every tenant. For a proposed threshold T and nonnegative margin M, the audit compares classifications at T-M and T+M. A score flips exactly when `T-M <= score < T+M`. The lower endpoint is included; the upper endpoint is excluded because the classifier uses `score >= threshold`.

The audit reports total, clean and spam flips, per-tenant flip fractions, and pass/fail. The optional `-max-stability-flips` gate requires `-stability-margin` and is evaluated independently for **every tenant**, preventing a large tenant from hiding a smaller tenant's instability. The fraction is relative to the tenant's total labeled sample count, not just predicted spam. A failed gate returns a nonzero exit code with a machine-readable failure report, matching existing classifier gates. Invalid option combinations fail before reading the corpus or writing any report. Threshold overflow fails closed.

A margin of zero is valid but produces zero flips and is not a meaningful robustness test. This is a descriptive perturbation test, **not** an estimate of real-world drift, false-positive rates, confidence intervals, or classifier precision. Use representative independent clean/spam corpora and the existing Wilson false-positive, recall and precision gates alongside it. The evaluator never alters live policy.

## Verification and open gates

Source and tests were committed for `internal/qualification/stability_audit.go`, `internal/qualification/stability_audit_test.go`, `cmd/spamgate-classifier-eval/main.go` and `cmd/spamgate-classifier-eval/stability_cli_test.go`. CI and live-host execution must be inspected independently; commit presence is not test success.

Issues #1-#9 remain open until real Postfix/Dovecot mail disposition, durable delivery/failure injection, authentication conformance, classifier precision/recall and false positives, tenant policy enforcement, diagnostics, browser acceptance, backup/restore and native update/rollback pass their independent gates. Preserve `/opt/spamgate/spamgate`, `spamgate-worker`, `/opt/spamgate/data`, and Milter ports 38470/38472. No Docker substitution or automatic running mail-server configuration changes.
