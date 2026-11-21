# Spool-trend verified-state accounting — 2026-11-21

Scope: native read-only diagnostic evidence only (issues #2 and #6). No change to Postfix, Dovecot, service supervision, Milter ports, or mail delivery.

## Defect and correction
Previously a report with `published=100` but only one verified queued state could be treated as a passing input, making queue-growth trends materially undercount the published spool. The `Load` path rejected state totals above published but not below published. `Compare` also accepted caller-constructed snapshots with negative, unknown, or inconsistent counts.

Both paths now require that the sum of all allowed verified state counts equals the published count. Direct callers also require nonnegative counts and feasible pending/published/examined accounting. The existing overflow guard is retained.

Regression cases cover incomplete published accounting, unknown states, negative state counts, and impossible pending counts. Existing growth tests now use internally consistent fixture totals.

## Verification boundaries
GitHub commits establish source publication, **not** successful compilation or test execution. This environment's GitHub DNS resolution failed and its local Go 1.23.2 toolchain is below the repository's declared version. Final-head CI must be inspected independently. The audit itself is read-only and is not a transactionally coherent live queue snapshot; passing trend evidence cannot prove final mailbox delivery.

Production issues #1–#9 remain open pending real Postfix/Dovecot end-to-end evidence, crash/retry qualification, protocol conformance, classifier corpus metrics, tenant isolation, browser acceptance, diagnostics fault injection, and native backup/update/rollback qualification.
