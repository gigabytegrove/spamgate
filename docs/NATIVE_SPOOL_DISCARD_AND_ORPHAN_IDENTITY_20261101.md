# Native SMTP spool deletion and orphan identity hardening — 2026-11-01

## Production gate

Issues #2 (durable delivery) and #6 (diagnostics). This is an incremental safety change, **not** production or long-term beta qualification.

## Accepted SMTP originals

The legacy `DeliveryQueue.Discard(id)` method formerly unlinked an accepted RFC 822 original without an actor, a durable discard-intent transition, or a history audit. It is now fail-closed for valid IDs and preserves the original bytes. Operational deletion remains available exclusively through `DiscardWithAudit(id, actor)`, which persists `discard_pending` before audit and unlink. Invalid queue IDs still return `os.ErrNotExist`.

Actor names are bounded to 128 UTF-8 bytes and reject invalid UTF-8, Unicode control/format characters, and invisible non-ASCII whitespace. Ordinary Unicode names and ASCII spaces remain accepted. Failed validation occurs before any queue mutation.

## Read-only orphan forensic checks

The native `spamgate-spool-audit` command now detects multiple `.pending-*` files with the same embedded queue ID. Identical immutable originals yield `pending_duplicate`; different immutable originals yield `pending_id_collision`. Reports expose only quoted filesystem names, counts and fixed descriptions, never SMTP envelope or message bytes. New JSON fields are `pending_duplicate_ids` and `pending_conflicting_ids`; human output includes both. The command never promotes, removes or retries unpublished records.

## Evidence and limitations

New tests cover legacy deletion refusal, unchanged original bytes, actor-injection refusal, valid Unicode audit, duplicate/colliding pending records, report privacy and read-only behavior. Existing queue and integration suites must still pass on the exact commit.

A pending file cannot prove that SMTP 250 was returned or whether an upstream relay accepted the message. Never auto-replay pending files. Production crash injection, real disk-full and actual mail-host recovery remain outstanding. This change does not alter `/opt/spamgate/spamgate`, `spamgate-worker`, `/opt/spamgate/data`, or Milter ports 38470/38472; it does not touch a running Postfix/Dovecot service.
