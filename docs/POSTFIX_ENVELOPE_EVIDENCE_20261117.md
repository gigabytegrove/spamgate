# Native Postfix envelope evidence hardening — 2026-11-17

## Scope and verified source changes

Starting main HEAD: cac46a126f7085c77e94728b85546dab2f42cfda.

The common native/injected Postfix HOLD inventory validator now rejects sender and recipient fields containing ASCII control bytes (0x00–0x1f), DEL (0x7f), padding, and fields longer than 1024 bytes. A blank sender is retained as valid for the RFC SMTP null reverse path (DSNs), while a blank recipient remains invalid. Literal backslashes are preserved; no escape decoding is performed. The existing queue ID, arrival, size, count, duplicate-ID, and truncation checks remain enforced. This protects both read-only inventory correlation and privileged release authorization, which share the validator.

The test suite now covers sender escape injection, padding and oversized values, recipient tab/DEL/escape/oversized values, null reverse paths and literal backslashes.

## Qualification evidence and limitations

GitHub file updates returned commit SHAs; these are source-write evidence, not test success. Local git clone failed with DNS resolution for github.com and the available local Go version was 1.23.2, below the repository toolchain requirement. No local Go tests or production mail-host tests were executed. GitHub CI for exact final HEAD must be inspected separately. No Postfix, Dovecot, ISPConfig, Milter, systemd or live mail configuration was modified.

Issues #1–#9 remain open until their independent acceptance requirements are met. In particular, real Postfix HOLD release, mailbox placement, durable delivery crash recovery, SMTP/authentication conformance, classifier precision/false positives, tenant enforcement, browser regression, backup/restore and native update/rollback are not certified by this change. The October 31 beta target has passed; do not declare readiness without complete end-to-end and regression evidence.

Locked architecture: /opt/spamgate/spamgate foreground launcher, spamgate-worker, persistent /opt/spamgate/data, Postfix Milter ports 38470/38472, native Linux only for this target, and no automatic running mail-server changes.
