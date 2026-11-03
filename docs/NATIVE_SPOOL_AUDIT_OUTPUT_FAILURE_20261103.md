# Native spool audit output-failure contract — 2026-11-03

The read-only `spamgate-spool-audit` command must not return success when its report cannot be delivered to a caller. Previously, text-mode writes were unchecked, so a broken pipe, full output filesystem, or failing monitoring writer could be mistaken for a clean queue.

The CLI now uses the same explicit status semantics as the event auditor: exit 0 for a complete report with no findings; exit 1 for a successfully emitted report with spool findings; exit 2 for invalid invocation, failed audit, or failed report output. A report output failure takes precedence over a finding exit. JSON encoder errors are also exit 2. Tests inject zero-byte and partial writer failures and verify both text and JSON modes, plus the findings case.

This change does not modify spool contents, retry messages, promote pending records, or reconfigure Postfix/Dovecot. It is a diagnostics gate only. Host-level delivery durability, backup/restore, independent Postfix queue-state verification and exact-commit CI remain separate qualification requirements.
