# Signed backup manifest decoding hardening — 2026-11-18

Issue #8, native Linux architecture unchanged.

## Implemented
- Signed JSON manifests are scanned token-by-token before normal strict schema decoding.
- Duplicate JSON object keys are rejected at every nesting level, including the root, manifest object, and file entries. Go's default JSON decoder otherwise accepts repeated keys and silently selects a later value.
- JSON input is bounded to 16 MiB, including trailing whitespace; a one-byte overread detects oversized documents.
- Nested JSON depth is limited to 32. Unknown fields, trailing JSON values, invalid inventory paths and malformed checksums remain rejected.
- Existing HMAC authentication continues to occur before opening any backup files. No changes to Postfix, Dovecot, service management, running mail, or stored data.

## Tests added
Nested duplicate keys, top-level duplicate authenticator, valid decode, oversized whitespace, and unknown nested fields.

## Evidence and limitations
These are committed regression tests; successful execution must be confirmed by final-HEAD CI. A local repository checkout is unavailable because github.com DNS resolution fails in the execution container. GitHub's commit-workflow lookup only reports pull-request runs, so an empty result cannot establish that push CI did not execute.

This is still a read-only verification library, not a complete native backup/restore workflow. Missing gates include snapshot consistency, complete inventory, protected key escrow, cold restore, ownership/permissions recovery, native update/rollback and actual mail-host evidence. Issues #1–#9 remain open. Do not call this beta-qualified.
