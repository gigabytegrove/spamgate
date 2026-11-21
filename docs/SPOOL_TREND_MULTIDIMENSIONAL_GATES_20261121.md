# Native spool-trend multidimensional qualification — 2026-11-21

The read-only trend command can now fail on growth of queued, dead, delivering and unpublished pending messages, as well as the absolute number of dead messages in the later snapshot. Each threshold defaults to -1 (disabled). Equality passes. Violations return exit 1 with JSON gate_failures; invalid evidence or arguments return exit 2.

This is an operational diagnostic, not proof of SMTP acceptance, durable delivery, final mailbox placement or snapshot chronology. Inputs must independently pass the spool-audit integrity gate. The caller is responsible for capturing ordered reports from the same trusted host and data root. No live Postfix, Dovecot, ISPConfig, or service configuration is modified.

Run go test ./internal/spooltrend ./cmd/spamgate-spool-trend using the Go toolchain specified by go.mod; inspect exact-commit CI. Real-host acceptance and issues #1–#9 remain open.
