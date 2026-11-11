# Postfix privileged subprocess preflight — 2026-11-10

Issue: #9 (also affects #1). The Linux `spamgate-postfix-release` helper executes a fixed `postsuper -H <queue-id>` command through the existing privilege boundary. This change makes `runPostsuperCommand` reject a nil context, already-canceled or expired context, and a typed-nil result writer **before** executing a subprocess. A typed-nil writer in an `io.Writer` interface previously passed the ordinary nil check and could panic after an irreversible queue operation.

Regression fixtures create a marker file if a subprocess starts, then assert that all four invalid preflight cases reject execution. This is source-level safety work, not evidence that a real Postfix queue item was released or delivered.

The established native architecture remains `/opt/spamgate/spamgate` as foreground launcher, `spamgate-worker`, persistent `/opt/spamgate/data`, and Postfix Milter ports 38470/38472. No mail-server configuration is modified.

## Qualification still required

- Execute Linux Go regression tests and inspect exact-HEAD CI, including Postfix/Dovecot disposable-host integration.
- Independently verify a correlated held queue ID, owner/recipient isolation, ID reuse resistance, privileged helper installation and rollback, and actual delivery/Junk placement on a controlled mail host.
- Preserve all other open production gates: durable delivery, SMTP/authentication compliance, classifier detection and false-positive measurement, tenant enforcement, diagnostics, browser acceptance, backup/restore and native update/rollback.

Do not close issues #1–#9 or claim beta qualification based on this preflight change.
