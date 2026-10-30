# Durable queue mutable-state integrity — October 30, 2026

The native SMTP outbox now stores two independent corruption-detection hashes.
`integrity_sha256` covers the immutable RFC 5322 bytes, scan evidence and
envelope. `state_sha256` covers delivery state, retry count, backoff timestamp,
subject, size and delivered timestamp. Each durable state transition rewrites
the state hash before the atomic rename and directory fsync.

A mismatched digest blocks startup, queue listing and forwarding. Legacy queue
records without the new state hash remain readable and gain it at their next
state transition. These hashes are **not keyed MACs**: an operator with spool
write permission can recalculate them. Spool permissions remain owner-only.

Malformed `*.json` directories and invalid job filenames now fail closed
rather than being silently skipped. Delivery finalization propagates journal,
file-removal and directory-sync errors for operational diagnosis. Upstream SMTP
250/crash ambiguity still means **at-least-once**, not exactly-once.

Tests mutate persisted JSON without recomputing the digest, verify forwarding
is blocked, exercise legacy migration, and check refusal on a fake job
directory. Real host power-loss and Postfix/Dovecot tests remain separate.
