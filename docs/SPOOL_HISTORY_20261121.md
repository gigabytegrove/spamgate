# Native spool history qualification — 2026-11-21

## Scope and evidence

The read-only `spamgate-spool-history` command compares **every adjacent interval** in a series of 2–1024 independently captured `spamgate-spool-audit -json` reports. This closes a diagnostic blind spot in two-point comparisons: a queue surge that subsequently drains can be invisible when only the first and last observations are compared.

Build: `go build -o spamgate-spool-history ./cmd/spamgate-spool-history`.

Example (no mail-server configuration or queue mutation):

```sh
spamgate-spool-history \
  -report /opt/spamgate/data/diagnostics/audit-001.json \
  -report /opt/spamgate/data/diagnostics/audit-002.json \
  -report /opt/spamgate/data/diagnostics/audit-003.json \
  -max-queue-growth 100 \
  -max-dead-growth 0 \
  -max-delivering-growth 50 \
  -max-pending-growth 0 \
  -max-dead-count 0 \
  -max-snapshot-gap 30m \
  -max-snapshot-age 15m
```

The paths above illustrate an operator-supplied layout; this change does **not** create a scheduler, write audit reports, or install any service. The command accepts repeated `-report` flags, requires timestamps and strictly increasing capture times, rejects aliased report files, checks each report's existing integrity gate, enforces interval gap and final-sample age, and reports peak counts, largest positive changes and indexed interval failures. Exit status: 0 qualified, 1 operational threshold exceeded, 2 invalid input or evidence.

## Implementation and regressions

- `internal/spooltrend/series.go`: bounded chronological analysis, integrity checks, interval evaluation and privacy-limited aggregate results.
- `internal/spooltrend/series_test.go`: transient growth hidden by endpoints, chronology, age/gap, invalid middle observation and size bound.
- `cmd/spamgate-spool-history/main.go`: native read-only CLI with explicit limits and file-alias refusal.
- `cmd/spamgate-spool-history/main_test.go`: executable CLI failure-path and hard-link regressions.
- `.github/workflows/engineering-qualification.yml`: native amd64 build and three-snapshot transient-growth smoke gate.

## Remaining qualification boundaries

This is **not** proof of accepted-message durability, final Dovecot mailbox placement, authenticated report provenance, transactional snapshot consistency or production-host readiness. The existing audit input format is retained, including legacy compatibility in the two-point tool; the new series tool deliberately requires timestamps. Concurrent in-place modifications and malicious parent directories remain separate threat-model gaps. All issues #1–#9 remain open pending their independent acceptance criteria.

The fixed native launcher, worker, persistent data directory and Milter ports are unchanged. No Docker substitution, mail-host configuration changes or service restart are included.
