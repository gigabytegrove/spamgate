# Event audit nested JSON evidence integrity — 2026-11-03

Production gate: #6 (diagnostics). The read-only `spamgate-event-audit` command now rejects duplicate JSON object keys at any nesting level, including Unicode-escaped aliases. Previously only top-level duplicate keys were rejected, allowing conflicting findings and metadata objects to be accepted with Go's last-value-wins behavior.

The parser uses streaming `json.Decoder.Token` traversal and per-object key sets. It rejects nesting deeper than 64 levels, preserving a bounded recursion depth. Records failing validation increment `malformed` and do not contribute to disposition counts. Distinct nested findings continue to count normally.

Regression tests: `go test ./cmd/spamgate-event-audit`. Full repository, native build and Postfix/Dovecot integration workflows must pass on the final commit before this is considered CI-verified.

This is diagnostic integrity hardening only. JSONL events remain unauthenticated and cannot independently prove Postfix HOLD or mailbox delivery. No production mail-host testing, mail server configuration changes, Docker substitution, or deployment are authorized by this change. Native launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, persistent `/opt/spamgate/data`, and Milter ports 38470/38472 remain unchanged.
