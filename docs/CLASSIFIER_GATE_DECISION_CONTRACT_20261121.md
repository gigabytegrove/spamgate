# Classifier qualification decision contract — 2026-11-21

Scope: GitHub issue #5, classifier corpus comparator only. This is not production classifier or mail-host qualification.

The `spamgate-corpus-compare` JSON report now contains `gate_passed` (boolean) and `gate_failures` (ordered string array). This prevents automation from treating a valid JSON report as proof of acceptance when the process exits 1. All independent aggregate and enabled tenant gates are evaluated; reasons are deterministic, with tenant names sorted lexicographically. A successful run emits `gate_passed:true` and an empty list. An acceptance failure emits `gate_passed:false`, explicit reason codes and exit 1. Invalid CLI or malformed corpus evidence exits 2 without a qualification report.

Tenant sample insufficiency is now a qualification failure (exit 1 with JSON), not a parser failure (exit 2). Missing tenant identity is likewise an explicit failed gate when `-require-tenants` is active. Gate configuration remains validated before reading input. No live Postfix/Dovecot configuration is touched.

Security boundary: reason codes may contain tenant identifiers from evidence, so treat reports as sensitive operational data. JSON must not be used to override process exit codes; require both exit 0 and `gate_passed:true` for acceptance.

Evidence limitations: synthetic paired corpora only; the comparator does not execute production classification, verify label provenance, or establish representative false-positive rates. The native worker, launcher, ports, data layout and mail host remain unchanged.

Qualification required: `go test ./cmd/spamgate-corpus-compare`, repository-wide tests and race tests, CI at exact HEAD, representative independently labeled corpus, and production mail-host acceptance.
