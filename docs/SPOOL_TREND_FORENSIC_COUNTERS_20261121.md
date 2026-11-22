# Spool-trend forensic counter integrity — 2026-11-21

Scope: issue #6 (diagnostic integrity), supporting issue #2 (delivery evidence).
The native read-only spool-trend comparator now refuses a report marked
`gate_passed=true` when any forensic anomaly counter is nonzero, even if the
report's `findings` array is empty. The check applies to file-loaded and
programmatically constructed snapshots.

Counters: pending_without_final, pending_with_final, pending_duplicate_ids,
pending_conflicting_ids, lifecycle_anomalies, legacy_unsigned,
unreadable_records, invalid_filenames, unexpected_entries, dropped_findings.

Regression coverage: table-driven tests exercise each counter in direct
comparison and JSON file loading. Existing zero-valued and legacy reports
remain compatible. Missing counters are treated as zero for compatibility;
the report is not cryptographically authenticated, and this gate does not
establish provenance or final delivery.

Architecture unchanged: /opt/spamgate/spamgate foreground launcher,
spamgate-worker, /opt/spamgate/data, Postfix Milter 38470/38472.
No Docker substitution and no running mail-server changes.

Verification limitations: GitHub source and commits inspected; local clone
failed because github.com DNS resolution is unavailable and local Go 1.23.2
is below the repository's go 1.27.4 requirement. No production host test.
CI success must be independently confirmed for final HEAD.

The October 31 beta target has passed. All issues #1-#9 remain open and
beta qualification remains blocked on real-host mail disposition,
crash/durability fault injection, protocol/authentication interoperability,
classifier false-positive corpora, tenant enforcement, browser acceptance,
backup/restore and native update/rollback.
