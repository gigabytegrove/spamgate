# Read-only native spool trend qualification

`spamgate-spool-audit -json -dir /opt/spamgate/data/delivery-queue > before.json` and a later invocation can produce two independent observations. Run `spamgate-spool-trend -before before.json -after after.json -max-queue-growth 100 -max-dead-growth 0` to compare verified queue counts.

The command refuses failed, incomplete or malformed reports, reports signed-state count deltas without exposing message contents, and exits 0 for passing thresholds, 1 for breached thresholds and 2 for invalid evidence or output errors. Capture files must be stored with restrictive permissions by the operator. A report's `gate_passed` is a local audit result, not production mail-host qualification. Reports have no trusted capture timestamp; operators must enforce chronological ordering and provenance externally. Live audits are not transactionally consistent. No mail-server settings, Postfix queue contents or Dovecot mailboxes are changed.

Remaining gates: actual durable delivery and crash recovery, final mailbox disposition, SMTP authentication, production classifier corpus accuracy, tenant enforcement, UI browser acceptance, cold backup/restore and native update/rollback. Do not close issues #1–#9 from this diagnostic alone.
