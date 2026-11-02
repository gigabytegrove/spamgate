# Native delivery-policy state integrity — 2026-11-02

## Production gates
Issues #3 (SMTP enforcement), #6 (diagnostics), and #4 (tenant/recipient policy lifecycle). This is an incremental protection, not policy qualification.

## Failure mode
The persisted greylist/rate-limit file previously used permissive JSON unmarshalling: duplicate or case-folded keys could silently override counters, and malformed or unexpectedly large data could be accepted or consume unbounded startup resources. The live evaluator also checked the 20,000-key capacity before adding a new triplet, permitting a 20,001st key to be committed.

## Implementation
- Require a regular, unchanged-on-open file; reject symlinked, nonregular, or >16 MiB policy evidence.
- Validate complete JSON, Unicode escapes, duplicate/case-folded keys, and trailing values with the shared spool JSON validator.
- Disallow unknown top-level fields; validate 64-character lowercase SHA-256 keys, nonzero timestamps, per-map 20,000-key ceilings, 100,000 timestamps per IP, and 200,000 total retained timestamps.
- Refuse corrupt evidence at startup without rewriting or resetting counters. Missing state remains a legitimate fresh install.
- Apply the same state validator to both startup reads and pre-commit writes. This prevents runtime growth from publishing a counter file that the next restart cannot read, including the shared 200,000 timestamp ceiling; preserve in-memory counters on refusal.
- Add cold-open, corruption, read-only refusal, symlink, size and capacity regression coverage.

## Verification boundaries
Tests are not proof of a live ISPConfig/Postfix/Dovecot host. Real fault-injected mail flows, high-volume retention, concurrent-process enforcement, and tenant-specific policies remain unqualified. The existing JSON state format is unchanged; older ambiguous/corrupt files now require evidence-preserving operator investigation rather than automatic repair. No mail-server settings are modified by this change.
