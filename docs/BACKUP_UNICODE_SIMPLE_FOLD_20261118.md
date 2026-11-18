# Unicode simple-fold backup identity — 2026-11-18

## Scope
Backup source traversal and manifest semantic validation now use a shared Unicode SimpleFold-cycle canonical identity rather than `strings.ToLower`. This closes a portability gap for names that compare equal under Unicode simple folding but do not share the same lowercase representation, notably `K` versus `K` and `S` versus `ſ`. The change is fail-closed and does not rename or mutate live data.

## Files
- `internal/backup/portable_fold.go`: canonical Unicode simple-fold identity.
- `internal/backup/backup.go`: source-wide identity inventory, including empty directories.
- `internal/backup/manifest_semantics.go`: manifest duplicate and file/directory ancestor identity checks.
- `internal/backup/portable_fold_test.go`: canonicalization and manifest adversarial regressions.

## Evidence and limits
The canonicalization algorithm was independently exercised with local Go 1.23.2 for Kelvin sign, long s, Ä/ä and ASCII case variants. This is **not** a repository-wide Go test, which requires the repository's newer toolchain and full source. New repository tests are committed but their execution and final-HEAD GitHub Actions result must be checked separately. No real cold restore or mail host was tested.

Unicode simple folding does not model every filesystem's normalization (notably decomposed versus precomposed names), and existing version-one backups with ambiguous names may now fail verification. Do not rewrite archives automatically; remediate the offline source names and create a fresh verified backup. Empty directories remain excluded from the version-one archive payload.

## Architecture and release gates
No change to the permanent foreground launcher `/opt/spamgate/spamgate`, `spamgate-worker`, `/opt/spamgate/data`, Postfix Milter ports 38470/38472, or the running mail server. Issues #1–#9 remain subject to independent end-to-end and production-host qualification. The 2026-10-31 beta target has passed; this change is not a beta readiness declaration.
