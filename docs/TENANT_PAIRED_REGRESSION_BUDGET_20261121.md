# Tenant paired regression budgets — 2026-11-21

Issue #5 classifier qualification and issue #4 tenant isolation. The native `spamgate-corpus-compare` command now accepts `-max-tenant-new-fp=N` and `-max-tenant-new-fn=N` alongside `-require-tenants`. The defaults are -1 (disabled) to preserve existing invocation semantics; explicit zero refuses any newly misclassified message in that class in **each** tenant, regardless of aggregate improvements or corrected messages. Values below -1 are invalid (exit 2); an exceeded budget returns exit 1 with JSON evidence. These options cannot be supplied without tenant enforcement. Each tenant must still have minimum clean and spam sample counts and satisfy the existing candidate error-rate and Wilson bounds.

Example: `go run ./cmd/spamgate-corpus-compare -baseline baseline.jsonl -candidate candidate.jsonl -require-tenants -min-tenant-clean 100 -min-tenant-spam 100 -max-tenant-new-fp 0 -max-tenant-new-fn 0`.

Scope: offline labeled JSONL comparison only. The comparator **does not** invoke the production SpamGate classifier, prove corpus representativeness, authorize live mail disposition, or certify tenant runtime policy. Regression coverage added for per-tenant aggregate masking, both classes, invalid negative limits, explicit disabled tenant enforcement, inclusive budgets and emitted failure evidence.

Locked native Linux runtime is unchanged: `/opt/spamgate/spamgate` foreground launcher, `spamgate-worker`, persistent `/opt/spamgate/data`, Postfix Milter ports 38470/38472. No mail server or service changes.

Qualification outstanding: run full Go tests, race tests, vet, exact-HEAD GitHub engineering CI, isolated Postfix/Dovecot mail lab, representative independently labeled corpus, and production host acceptance. Issues #1-#9 remain open until their own end-to-end gates pass. October 31 target has passed; no beta-ready assertion.
