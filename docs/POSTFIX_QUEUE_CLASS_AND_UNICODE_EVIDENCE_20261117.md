# Postfix queue-class and Unicode evidence hardening — 2026-11-17

## Scope

The native `postqueue -j` parser now refuses queue names outside the supported `maildrop`, `incoming`, `active`, `deferred`, and `hold` classes. Before this change, a misspelled or spoofed `hold` class was silently skipped as a non-HOLD record, potentially yielding misleading authorization evidence. Queue identifiers are still checked across all entries. Unknown classes fail closed rather than being ignored; Postfix compatibility must be rechecked against each deployed version before release.

The shared envelope evidence validator additionally refuses Unicode whitespace within sender/recipient identity evidence (including non-breaking and ideographic spaces), while preserving ordinary SMTPUTF8 mailbox identities. It continues to permit the empty sender for DSNs.

## Source and regressions

- `internal/server/postfix_hold.go`: explicit queue-class allowlist at native inventory parsing boundary.
- `internal/server/postfix_native_inventory_boundary_test.go`: unknown, case-spoofed, padded and supported queue-class fixtures.
- `internal/server/postfix_release_inventory.go`: Unicode whitespace rejection.
- `internal/server/postfix_release_inventory_test.go`: sender and recipient Unicode whitespace fixtures.

## Evidence and outstanding gates

These source changes and regression fixtures were committed to `main`; they are not evidence that Go tests, GitHub Actions, or a live Postfix/Dovecot host passed. Local repository cloning was blocked by DNS resolution of github.com. GitHub commit-status lookup returned no statuses at inspection. Do not treat this change as host qualification or close issues #1–#9.

Still required: final-HEAD Go/race/vet and isolated Postfix/Dovecot CI, version-specific `postqueue -j` queue-class compatibility, actual held-message release and downstream mailbox proof, durable-delivery fault injection, SMTP authentication vectors, classifier false-positive corpus, tenant enforcement, browser acceptance, native backup/restore and update/rollback.

No mail-server configuration was changed. The permanent foreground launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, persistent `/opt/spamgate/data`, and Milter ports `38470/38472` remain the architecture.
