# Policy replay: bounded historical score evidence (2026-11-12)

Production gate: tenant policy replay and diagnostics (#5/#6). Historical final scores are untrusted persisted evidence, not current scanner outputs. The replay now treats scores below zero, above 1000, NaN, and infinities as indeterminate. These records cannot contribute hypothetical verdict counts or preserve a forced verdict as though the score were valid. Their numeric JSON score is sanitized to zero only when non-finite; the indeterminate flag and note are authoritative.

The change is confined to the read-only policy preview; it does not change live Milter disposition, Postfix, Dovecot, threshold configuration, or on-disk history. Tests cover boundary values, out-of-range and non-finite inputs, JSON serialization and invalid-score forced-action isolation.

Verification is limited to source review until exact-HEAD CI completes. The acceptance gates for real Postfix/Dovecot delivery and holds, durable delivery, SMTP authentication, classifier false positives, tenant policy enforcement, full browser UI, backup/restore and native update/rollback remain open. No production host was touched.
