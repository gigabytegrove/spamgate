# Native spool audit JSON qualification contract — 2026-11-21

The read-only `spamgate-spool-audit -json` report now includes `gate_passed` (boolean) and optional `gate_failures` (ordered strings). The decision is false if any integrity finding or configured queue threshold fails. An empty queue with no findings passes. The existing spool report keys remain intact.

`gate_failures` contains threshold failures only; integrity evidence remains in `findings` and `finding_counts`. Consumers MUST check `gate_passed === true` and process exit status 0; parsing valid JSON alone is not qualification. Exit 1 denotes a complete audit with failed gates, while exit 2 denotes input, scan or output failure and must never be interpreted as a clean audit. No JSON is guaranteed on exit 2.

The scan is a bounded, read-only observation, not an atomic filesystem snapshot or delivery acknowledgement. It does not retry, release, delete, modify, or certify any message. No production Postfix/Dovecot host was exercised. This change addresses machine-readable operational diagnostics for issues #2 and #6, not end-to-end delivery qualification.

Tests added for clean, threshold-exceeded and integrity-finding cases. At commit time, test execution and final-HEAD CI were not yet verified.
