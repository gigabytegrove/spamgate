# Native event audit evidence hardening — 2026-11-03

## Scope
Production gate #6: read-only JSONL diagnostics. No mail-host configuration, Milter, or runtime launcher changed.

## Defects and correction
The previous engineering workflow (run 41586820822) failed TestAuditAcceptsDistinctNestedEvidence because a regression fixture appended the two literal characters backslash and n rather than a newline. The earlier nested duplicate fixtures used the same defective line ending and therefore could pass merely because their JSON was invalid. Fixed those fixtures to use actual JSONL newlines, and corrected Unicode-alias fixtures to exercise escaped JSON keys.

Go encoding/json matches struct fields case-insensitively; a record containing both action and ACTION can otherwise be interpreted using last-wins behavior even without identical JSON object keys. The audit decoder now rejects case-folded duplicate top-level fields. It also rejects invalid UTF-8 input before encoding/json can replace malformed bytes with U+FFFD.

## Verification contract
Run `go test -count=1 ./cmd/spamgate-event-audit`, `go test -count=1 ./...`, `go test -race ./...`, and `go vet ./...`. Verify the exact final HEAD workflow and read the job logs. This is a diagnostic integrity change only: event counts remain untrusted as independent Postfix HOLD or Dovecot delivery proof.

## Outstanding
All nine production gates remain open. Production ISPConfig disposition, durable delivery under failure injection, authentication conformance, classifier precision/recall, tenant policy lifecycle, full browser acceptance, backup/restore drills, and native update/rollback require separate qualification.
