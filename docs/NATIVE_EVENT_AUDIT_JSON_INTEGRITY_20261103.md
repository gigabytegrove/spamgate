# Native event-history audit integrity — 2026-11-03

Production gate: #6 (diagnostics), with relevance to #1 (Postfix disposition evidence).

The read-only `spamgate-event-audit` utility previously used `json.Unmarshal` directly on each JSONL line. Go accepts duplicate JSON object keys with last-wins semantics. A record such as `{"connector":"milter","action":"accept","action":"quarantine"}` could therefore be counted as unambiguous evidence even though the record contradicts itself. Unicode-escaped aliases of keys had the same ambiguity.

The event decoder now checks all top-level keys using the decoded key names before unmarshalling the typed event. It also rejects non-object records, trailing JSON values, invalid typed fields and malformed non-null Milter findings arrays. Rejected lines increment the existing `malformed` counter and never enter Milter totals. Non-Milter connectors remain excluded from Milter totals. The scanner's existing 2 MiB per-line limit remains in force.

Regression coverage includes duplicate literal and escaped keys, invalid findings, invalid score types, non-object records, concatenated JSON objects and valid Milter/non-Milter controls.

Qualification command: `go test ./cmd/spamgate-event-audit`. This commit does not establish independent Postfix HOLD confirmation or authenticity of JSONL history; records remain operator-controlled and must be correlated with queue IDs and Postfix logs. No production mail-host configuration or running service is changed.

Architecture remains native: `/opt/spamgate/spamgate` foreground launcher, `spamgate-worker`, persistent `/opt/spamgate/data`, Milter ports 38470/38472. All nine cumulative production gates remain open until real-host evidence and end-to-end regression qualification exist.
