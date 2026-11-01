# Native spool Unicode key alias integrity — 2026-11-01

## Production gate
Issues #2 (durable SMTP delivery) and #6 (forensic diagnostics). This is a
source-level integrity correction, **not** mail-host or long-term beta
qualification.

## Reproduced root cause
Go encoding/json accepts object keys by Unicode simple case folding when
matching struct fields. For example, U+017F LONG S is equivalent to ASCII
"s" in `strings.EqualFold` and can overwrite `state` when decoding
`{"state":"dead","ſtate":"queued"}`. The existing spool JSON duplicate-key
validator used `strings.ToLower`, which does not fold U+017F to ASCII.
Consequently, a record containing contradictory keys could decode to the
original queued state with both immutable and mutable SHA-256 digests still
matching. Digests calculated over decoded structs cannot detect this alias.

## Implementation
All JSON object keys are now normalized using Unicode SimpleFold equivalence
before duplicate detection, including nested keys and escaped Unicode key
spelling. The validator retains its existing bounded depth/token budget and
generic, non-disclosing diagnostics. It does not alter the spool schema or
legacy data; a newly detected ambiguous original remains on disk and is
never delivered automatically. The read-only forensic auditor shares the
validator and likewise refuses ambiguous records.

## Regression gates
- Unicode long-s, escaped long-s, Greek sigma and Kelvin sign aliases.
- Ordinary distinct Unicode keys remain accepted.
- Matching-digest durable queue mutation is rejected by inventory, delivery
  processing and startup; the original is retained.
- Forensic auditor reports unreadable_record without modifying the original.
- Full Go tests/race/vet, native builds, UI tests and isolated mail lab must
  be evaluated against the final commit; no production host is modified.

## Remaining qualification
Crash-injected delivery ambiguity and duplicate handling, real Postfix and
Dovecot disposition, independent authentication interoperability, classifier
precision, tenant enforcement, diagnostics, browser acceptance, cold restore,
native update and rollback all remain outstanding. This change does not
provide cryptographic authentication of records against a local adversary
able to rewrite both data and SHA-256 fields.
