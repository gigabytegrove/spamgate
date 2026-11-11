# Privileged Postfix release helper: syntax repair (2026-11-10)

## Defect and correction

The Linux `cmd/spamgate-postfix-release/main.go` source contained literal `\\n` escape sequences **outside** string literals in the post-execution cancellation branch. This is invalid Go syntax and blocks building the native privilege helper. The cancellation check and its surrounding comments now use actual line breaks. A parser regression in `main_test.go` checks the entrypoint with `go/parser`.

## Scope and evidence

This is a source-level correction; no live mail-host changes were performed. The helper still runs only with an explicit root privilege grant and a fixed `postsuper -H` invocation. The regression was committed; independent execution and exact-HEAD CI conclusions must be inspected before declaring it passing. This change does not demonstrate successful queue release or final delivery.

## Remaining qualification

Issues #1-#9 remain open. Required evidence includes real correlated Postfix HOLD/release and Dovecot Junk disposition on an isolated host; durable delivery failure injection; SPF/DKIM/DMARC/ARC interoperability; classifier false-positive and recall measurements; tenant policy enforcement; diagnostic fault tests; browser UI acceptance; and native backup/restore and update/rollback on representative hosts. Do not treat isolated helper tests as production acceptance.
