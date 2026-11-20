# Native backup verification JSON output — 2026-11-20

## Scope
Issues #6 and #8: expose a machine-readable success receipt from the existing native cold-backup verifier. The command remains read-only for verification and cold-only for restore. The running mail server is never reconfigured or restarted.

## Interface
`spamgate-backup-verify --operation=verify --backup=... --manifest=... --key-file=... --output=json`

Successful verification or cold restore writes exactly one JSON object with `operation`, `status=success`, `files`, `bytes` and `mail_services_changed=false`. The default `--output=text` preserves the existing operator receipt. Invalid output modes fail before filesystem access. Authentication and restore errors produce no success JSON; the command exits nonzero and writes the error to stderr.

The JSON contains no message bodies, manifest contents, paths or authentication material. It is an operator diagnostic receipt, **not** proof of final mail delivery, a signed audit record, or a host-qualification certificate.

## Verification boundaries
Standalone Go 1.23.2 tests of the reporting helper passed (JSON/text, invalid arguments, zero totals, writer failures). Full Go 1.27.4 module compilation and GitHub Actions for the final HEAD must be checked separately. No real production restore, mail-server change or rollback was performed.

## Remaining acceptance
Issues #1–#9 remain open; real Postfix/Dovecot disposition, crash/durability, authentication interoperability, classifier false positives, tenant policies, full browser workflows, operational alerting and native upgrade/rollback still require independent acceptance.
