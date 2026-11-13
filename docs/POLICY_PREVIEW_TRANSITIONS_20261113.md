# Policy preview transition evidence — 2026-11-13

The read-only threshold replay now returns `totals.transitions`, a nested map of historical verdict to candidate verdict counts. It includes unchanged verdicts and distinguishes `soft_reject` from `reject`. Invalid historical evidence is excluded from every transition. The response also exposes `sample_determinate` and `sample_indeterminate` for direct UI consumption.

This is a **sampled comparison of saved classifier verdicts**, not a confusion matrix against human-labeled truth. It cannot prove delivery, SMTP enforcement, classifier precision, or a false-positive rate. The history limit can truncate the retained population. No configuration, SMTP action, queue disposition or mail-server state is changed.

Verification required: run `go test ./internal/server` and full project engineering CI at the exact commit; separately qualify real Postfix/Dovecot behavior, tenant enforcement, false-positive ground truth, browser workflows, backup/restore and native update/rollback. No production host was touched by this change.
