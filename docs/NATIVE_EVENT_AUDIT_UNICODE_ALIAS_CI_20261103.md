# Native event audit: Unicode alias CI correction (2026-11-03)

## Observed failure

Engineering run 41593305890 failed in `TestAuditRejectsNestedDuplicateEvidence` and `TestAuditRejectsCaseAmbiguousEventFields`. The test fixtures used doubled backslashes in Go raw strings, so JSON contained a literal backslash rather than a Unicode-escaped key. The decoder consequently accepted the records. The isolated Postfix/Dovecot workflow 41593305840 passed; that does not qualify the failing engineering gate.

## Correction

Use single-backslash JSON Unicode escape sequences in raw-string fixtures. Reject nested JSON object keys that collide after ASCII case folding, matching the existing top-level event-field policy. Preserve distinct nested objects and valid findings arrays. The decoder remains read-only and does not authenticate the origin of JSONL records.

## Verification contract

Run `go test -count=1 ./cmd/spamgate-event-audit` and `go test -count=1 ./...`, followed by the full engineering qualification and isolated Postfix/Dovecot workflows on the exact final commit. Do not mark the gate passed until CI reports success and its job logs are inspected. Production-host disposition, durable delivery, authentication, and disaster recovery remain unqualified.

## Architecture preservation

No changes to `/opt/spamgate/spamgate`, `spamgate-worker`, `/opt/spamgate/data`, Postfix Milter ports 38470/38472, or the running mail server.
