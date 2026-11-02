# Crash-retained SMTP original identity admission gate — 2026-11-02

Scope: production gate #2 (durable accepted mail), with diagnostic implications for #6. This is engineering progress, **not** beta qualification.

## Failure prevented

The native intake lock and queue inventory already counted `.pending-*` records toward spool capacity, but Enqueue checked a new queue ID only against published `<id>.json` files. A crash-retained unpublished original with the same ID could therefore coexist with a newly accepted published original. That makes manual recovery and original attribution ambiguous.

Enqueue now independently reads and validates retained unpublished originals **inside the existing cross-process intake lock, after capacity checks and before writing or acknowledging a new original**. An ID represented by a retained original is reserved. Invalid, ambiguous, tampered, unreadable or incomplete retained evidence has unknown identity and fails intake closed; it must not be ignored. Valid pending evidence for a different ID does not block intake.

The check uses the existing bounded spool read, file metadata checks, duplicate/Unicode-alias JSON-key rejection, immutable and mutable SHA-256 checks, and explicit envelope/state bounds. It does not rename, delete, repair, replay, or send any message. Retained original bytes are not emitted to errors or logs.

## Qualification and operational tradeoff

Regression coverage exercises same-ID refusal, restart persistence, different-ID admission, ambiguous keys, digest tampering, incomplete crash evidence, evidence immutability and operator-cleared recovery. The exact-commit CI and disposable-host integration runs must be inspected independently.

A malformed pending original can temporarily prevent new SMTP intake; this intentionally returns an error rather than risking a second SMTP 250 against an unknown original. Operators must investigate using `spamgate-spool-audit` and preserve forensic evidence before any manual cleanup. Do not automatically delete pending files. This is not a transactional filesystem snapshot against an unrelated privileged process that ignores the intake lock.

## Deployment invariants

The native foreground launcher remains `/opt/spamgate/spamgate`; `spamgate-worker` uses `/opt/spamgate/data`. Postfix Milter ports remain 38470/38472. No Docker substitution, no production mail-server changes, no automatic Postfix/Dovecot restarts. Production-host and crash/power-loss qualification remain open.
