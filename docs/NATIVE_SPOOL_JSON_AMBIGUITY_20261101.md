# Native spool JSON ambiguity protection — 2026-11-01

Production gates: #2 (durable delivery), #6 (forensic diagnostics).

## Defect and consequence
The Go standard JSON decoder accepts duplicate object keys and uses the last value. A file containing both `"state":"dead"` and `"state":"queued"` could decode identically to the legitimate record. Since the existing SHA-256 delivery-state digest is calculated from decoded fields, it could still match. Nested scan evidence had the same ambiguity. The read-only spool auditor also needed the same validation.

## Implemented
- A shared bounded `internal/spooljson.Validate` parser checks the entire JSON document before ordinary decoding, including nested objects and arrays.
- Reject duplicate keys, including case-folded keys and escaped names that decode to the same key; reject invalid UTF-8, multiple top-level JSON values, non-object roots, nesting over 64 and token counts over 250,000.
- The delivery queue rejects ambiguous records during startup inventory, snapshot and worker processing, before relay. Original files remain untouched for operator inspection.
- The read-only spool auditor reports an `unreadable_record` finding rather than presenting contradictory state as valid.
- Existing unsigned legacy records remain readable when otherwise unambiguous; no automatic migration, deletion or replay.

## Verification and limitations
Local standalone Go race tests and vet of the shared validator are executable without the full repository. The full transport/spoolaudit integration and isolated Postfix/Dovecot lab must be verified on the exact pushed commit in GitHub Actions. No production mail host is accessed. SHA-256 is not a keyed MAC and cannot defend against a privileged attacker who can rewrite both a record and its digests. This is a data-integrity gate, not an at-most-once delivery guarantee.

The locked native foreground launcher, worker, persistent data directory and Milter ports remain unchanged.
