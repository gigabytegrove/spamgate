# Architecture

SpamGate deliberately separates **ingestion**, **analysis**, **policy**, **transport enforcement**, **audit storage**, and **management**:

```text
Trusted SMTP MTA -- SMTP filtering service -- scanner -- policy -- SMTP relay
                                                  |       |        \- quarantine
Custom MTA ------- authenticated HTTP API ---------+       \- decisions
                                                  |
                                                  +-- built-in heuristics
                                                  +-- custom rulebook
                                                  +-- optional DNSBL
                                                  |
                                          JSONL audit event store
                                                  |
                                          browser message inspector
```

The `internal/core` package owns message types, config validation, PBKDF2 password hashing, rule matching, DNSBL queries, scoring and atomic persistence. The `internal/transport` package handles a limited trusted-network SMTP connector and authenticated outbound SMTP/TLS transport. The `internal/server` package owns the first-run wizard, session security, role control, web UI and REST interface. `cmd/spamgate` wires the process together and coordinates shutdown and scheduled history compaction.

## Data consistency

One process owns the data directory. Config files use write-to-temp + fsync + rename. Message events append and fsync to JSONL. Repeated IDs represent audit updates; most recent event wins. On restart, the in-memory index is replayed from the journal. History is pruned by age and count. The current architecture is single-instance and does not yet include SQL transactions, distributed locking, schema migration, an SMTP spool or durable background jobs.

## Rule provenance and actions

Every signal carries a stable symbol ID, source, readable match description and numeric contribution. The sum is compared against escalating thresholds. Admin custom rules may set a forced action after threshold determination; last match wins. Explicit user rules are only evaluated for messages whose recipient list contains exclusively the rule owner's address. This avoids forcing an allow decision on unrelated co-recipients within one SMTP transaction. A future per-recipient decision engine will split multi-recipient transactions.

## Threat boundaries

A trusted SMTP client can submit RFC 5322 bytes and request delivery only to an explicitly allowlisted recipient domain. The scanning API returns a recommendation only; API bearer authorization does not imply SMTP relay privileges. SMTP is not a public MX or MSA server and does not implement inbound TLS/AUTH. The web console must be placed behind HTTPS in externally accessible environments. No third-party UI dependencies are loaded at runtime.

## Scaling path

Replace the local journal with a pluggable, transactional storage layer (SQLite for single-node, PostgreSQL for clusters), add a durable relay queue, separate ingestion/scoring/storage services only when concurrency or cluster demands justify them, add worker supervision and metrics, and then implement adapter-level protocol parity behind feature/version gates. Preserve the current findings schema as the basis of all explainability.
