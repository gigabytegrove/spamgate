# Controller training upload integrity — 2026-11-23

Starting immutable main revision: 753159afed7877d14201aa6070cda70ca42f626a.

## Implemented
- The Rspamd-compatible training endpoint now checks declared content length and bounds actual streamed bytes to 10 MiB.
- Empty samples are refused before classifier invocation.
- Cancelled requests receive HTTP 408; disconnected or unreadable uploads receive HTTP 400; excessive bodies receive HTTP 413. Previously every body read error was mislabeled as oversize.
- The upload reader closes the bounded body and never returns partial data on failure.
- Added table-driven boundary, transport-error, cancellation, and close regression tests.

## Qualification
- GitHub source commits: published through the connected GitHub integration.
- Native Go compilation: NOT EXECUTED. Available local Go is 1.23.2; the repository requires a newer toolchain.
- Full Go tests, race tests and vet: NOT EXECUTED.
- Owner-controlled native Linux builder: NOT EXECUTED (not accessible in this run).
- Live Postfix/Dovecot and end-to-end classifier training: NOT EXECUTED.
- GitHub Actions: PROHIBITED, not used, and not qualification evidence.

## Open acceptance
This does not close issues #1–#9. Prioritize durable queue crash recovery, real hold/release and Junk placement, SMTP/authentication interoperability, measured classifier false positives, tenant isolation, browser acceptance, cold restore and native rollback. Do not deploy or change production mail-server configuration based on these source changes alone.
