# Spool-trend independent-evidence identity guard — 2026-11-21

The native `spamgate-spool-trend` CLI now checks the filesystem identity of both report paths before loading either report. Different path strings pointing to the same inode (including hard links) return exit status 2 and no success JSON. Independently created regular files with identical contents remain valid legacy comparisons, subject to the existing timestamp and policy controls.

This is a defense against accidentally treating one captured audit report as two observations. It is **not** a provenance guarantee: a concurrent rename/replacement between the initial identity check and the individual opens remains possible, and distinct copies of the same report cannot be distinguished without stronger evidence binding. The current audit timestamp is not cryptographically authenticated.

Regression tests: `go test -count=1 ./cmd/spamgate-spool-trend`; full engineering gate: `go test -count=1 ./...` and the native GitHub Actions workflow. These commands are qualification instructions, not claims of completed execution.

The architecture remains unchanged: foreground launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, persistent `/opt/spamgate/data`, and Postfix Milter ports 38470/38472. No mail service is modified.

**Remaining production gates:** Issues #1–#9 are open. Real-host Postfix/Dovecot disposition, durable crash recovery, authentication interoperability, classifier false-positive corpus, tenant enforcement, browser acceptance, backup/restore and native update/rollback are not qualified by this change. October 31 beta target was missed. Do not release based on these diagnostics alone.
