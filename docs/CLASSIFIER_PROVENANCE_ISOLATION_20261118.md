# Classifier provenance isolation — 2026-11-18

## Implementation
The offline qualification package now provides `ValidateHoldoutProvenance` and `QualifyProvenanceHoldout`. Every sample must have exactly one matching provenance record with the same tenant, a nonempty family identifier, a lowercase 64-character SHA-256 digest, and an observation timestamp. Tuning and holdout sets must have disjoint sample IDs, disjoint message families and exact-content hashes, and a strictly chronological boundary (latest tuning observation before earliest holdout observation). Only then may the previously implemented frozen-threshold holdout gate run. The API never changes live policy.

## Evidence and limitations
The provenance fields are supplied by callers and are not independently authenticated. A malicious or mistaken producer can invent family identifiers, timestamps or digests. Near-duplicate detection is only as good as the externally assigned family IDs. This is an additional contamination guard, **not** independent production false-positive evidence. The tests use synthetic corpora; representative labeled mail and audited corpus provenance are still required.

## Qualification
Changes are source and regression tests, with no live mail-host modifications. CI and exact-commit build/test outcomes must be inspected before claiming a pass. No production-host acceptance is asserted.

## Locked native architecture
Permanent foreground launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, persistent `/opt/spamgate/data`, Milter ports `38470/38472`. No Docker substitution and no automatic running mail-server changes.

## Open acceptance gates
GitHub issues #1–#9 remain open: actual Postfix/Dovecot hold/release and mailbox disposition, durable mail acceptance and retry, SMTP/authentication compliance, classifier breadth and audited false positives, tenant policy enforcement, retained diagnostics, browser workflows, cold backup/restore and native update/rollback. The October 31 target has passed; beta is not qualified.
