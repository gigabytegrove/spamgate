# Native backup manifest JSON integrity — 2026-11-02

Production gate: #8 (native backup/restore and disaster recovery); secondary gate #6 (trustworthy diagnostics).

## Change
Version-1 backup manifest JSON is validated before Go struct decoding. The same bounded spool JSON validator already used for durable SMTP originals rejects duplicate keys, Unicode case-fold aliases, malformed UTF-8, lone UTF-16 surrogate escapes, excessive nesting/tokens, and trailing JSON values. A strict schema decoder also rejects unknown manifest and entry fields. ZIP payload hashes, file topology, size limits, symlink refusal, atomic no-replace publication, offline locks and restored-tree readback remain mandatory and unchanged.

## Regression contract
A forged ZIP with correct content and SHA-256 but ambiguous/invalid manifest must fail both Verify and Restore, and must not publish the requested destination. A normal version-1 manifest must verify and restore with byte-identical payload. No running mail server is modified.

## Limits
SHA-256 detects accidental or unauthorized byte changes only when the expected manifest is independently trusted. An attacker who can rewrite both payload and manifest can recompute hashes: backups are not signed or encrypted. This change is not production-host disaster-recovery certification. Full native systemd update/rollback, disk-full/power-loss injection, backup key management, independent host restore, ISPConfig integration and mail-host acceptance remain open. The October 31 beta target was missed; do not mark beta qualified.
