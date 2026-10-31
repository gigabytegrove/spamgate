# Native SMTP spool directory sync and read-only audit parity — 2026-10-31

Scope: production gates #2 (durable delivery) and #6 (diagnostics). Native Linux launcher, worker, persistent data root, Postfix Milter ports 38470/38472 and production Postfix configuration are unchanged.

## Corrected failure window

The queue previously synchronized the temporary record's file descriptor and renamed it without first synchronizing the temporary directory entry. If rename failed, or the post-rename directory fsync failed during a crash, the purportedly preserved `.pending-*` pathname was not itself proven durable. A file fsync is not a substitute for the containing directory fsync.

The queue now performs **file sync -> file close -> directory sync of the pending pathname -> validate existing destination -> rename -> directory sync of the published pathname**. If either directory sync fails, SMTP intake returns an error; no SMTP 250 is justified. A fully written pending file is left for forensic investigation on pre-rename failure. A published original remains on post-rename failure. Neither is automatically replayed, because the client's acknowledgement and the delivery state may be ambiguous.

Linux audit now matches the worker's published/pending record metadata checks: regular file, same opened pathname identity, owner-readable private mode, one hardlink, and effective-worker ownership. It reports unsafe files as `unreadable_record` without reading message content, modifying files, or claiming the queue is clean.

## Regression coverage

- Directory sync is observed before and after rename.
- Pre-rename sync failure returns an intake error and preserves a pending original.
- Post-rename sync failure returns an intake error and preserves a published original.
- Hardlinked published originals fail forensic audit and pass again after safe repair.
- Exposed published and pending originals fail forensic audit without leaking envelope/subject.

## Still not qualified

Tests with injected directory-sync failures do not simulate actual power loss, filesystem corruption, full-disk behavior, journal reordering or controller write caches. Remote SMTP 250 followed by a local crash remains an explicit at-least-once duplicate window. Live host delivery, independent authentication conformance, classifier false-positive evidence, tenant policy lifecycle, complete browser acceptance, cold restore and native update/rollback remain open. No production mail server is changed by this commit.
