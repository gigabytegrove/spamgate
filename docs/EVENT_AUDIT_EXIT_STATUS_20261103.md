# Event audit operational exit contract — 2026-11-03

Scope: `cmd/spamgate-event-audit`, read-only evidence analysis. No Postfix, Dovecot, queue or configuration writes.

## Exit status
- **0**: readable event history, no malformed JSONL records, no Milter quarantine decisions requiring independent Postfix confirmation.
- **1**: completed report with malformed records or unconfirmed Milter quarantine decisions. Reports remain available on stdout (including JSON); warnings go to stderr. This is a diagnostic gate, not proof of missing delivery.
- **2**: bad CLI arguments, inaccessible event history, stream read failure, or output write failure.

A quarantine action in SpamGate's event stream is a requested action, not independent Postfix HOLD proof. This tool intentionally cannot certify Postfix queue state.

## Tests
`go test ./cmd/spamgate-event-audit -count=1` exercises clean, malformed, quarantine, combined, unrelated SMTP, argument, missing-file and output-failure paths.

## Remaining qualification
Exact-commit engineering CI, isolated Postfix/Dovecot workflow, and production-host correlation of queue IDs to Postfix logs and queue state are separate gates. This change does not qualify a mail host, demonstrate fsync/power-loss recovery, establish classifier accuracy, or validate native updater rollback. Preserve `/opt/spamgate/spamgate`, `spamgate-worker`, `/opt/spamgate/data`, Milter ports 38470/38472; no Docker replacement or automatic live mail-server changes.
