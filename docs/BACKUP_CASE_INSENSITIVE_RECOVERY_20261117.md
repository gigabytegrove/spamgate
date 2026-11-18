# Case-insensitive native backup recovery identities — 2026-11-17

Issue #8 remains open. This change rejects v1 manifests whose file identities collide after Unicode lowercase conversion, including collisions between a file and a directory ancestor in either lexical ordering. The check is performed by `validateManifestSemantics` before restore publication; it does not rewrite source data or modify a running mail host.

## Evidence and boundaries

Implementation: `internal/backup/manifest_semantics.go`; regressions: `internal/backup/portable_path_test.go`. The check uses Go `strings.ToLower` for deterministic Unicode lowercase normalization, not full filesystem-specific Unicode normalization or full Unicode case folding. Additional APFS/HFS+ normalization and Windows short-name aliases are not certified. Paths in existing archives that conflict under these rules will be rejected, not silently renamed.

The runtime remains native: `/opt/spamgate/spamgate` foreground launcher, `spamgate-worker`, persistent `/opt/spamgate/data`, and Postfix Milter ports 38470/38472. No Docker replacement and no automatic live Postfix/Dovecot changes.

## Qualification still required

Execute Go tests, race tests, vet and native build at exact final HEAD. Verify a cold archive with a real data set, restore to a fresh directory, compare content, start the native worker and confirm Postfix/Dovecot delivery. Validate permissions and native update/rollback. Isolated CI is not real-host acceptance. Do not close issue #8 or declare beta-ready without that evidence.
