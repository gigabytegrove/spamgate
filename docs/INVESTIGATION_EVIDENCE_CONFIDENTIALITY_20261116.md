# Investigation evidence confidentiality — 2026-11-16

The message investigation endpoint previously embedded raw backend errors in its JSON evidence for retained-header reads, Postfix queue inventory, and configured mail-log reads. These errors can contain host filesystem paths and command diagnostics. They now emit fixed operator-facing messages and log the original errors on the server with scan identifiers.

The raw-header endpoint sets Cache-Control: no-store before authorization, including denial and missing-original paths. No live mail server settings, Postfix queue entries, or spool files are changed.

Regression source: internal/server/investigation_confidentiality_test.go. The missing-log fixture verifies that a private configured path is absent from the investigation response, while the denial fixture checks the raw-header cache policy.

Qualification limitations: these are API confidentiality controls, not evidence of real mailbox placement, privileged HOLD release, or complete browser workflow coverage. Run Go tests and the isolated Postfix/Dovecot lab on the exact commit, then obtain independent production-host evidence before closing issues #1–#9.
