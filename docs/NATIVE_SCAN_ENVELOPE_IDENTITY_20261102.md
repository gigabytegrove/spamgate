# Durable scan-envelope identity qualification — 2026-11-02

Production gates: [#2](https://github.com/gigabytegrove/spamgate/issues/2), [#6](https://github.com/gigabytegrove/spamgate/issues/6).

## Failure mode

An existing published or crash-retained original could contain a scan snapshot with the correct queue ID but a different sender or recipient vector. The immutable checksum includes that scan, so a record generated with internally inconsistent fields could still pass both unkeyed digest checks. A recovery path could then reconstruct incorrect history from that scan. The relay envelope remained authoritative, but diagnostic and policy evidence could be misleading.

## Implemented contract

* For published and unpublished originals, a present scan must match the durable ID, exact sender and ordered recipient vector, including multiplicity.
* Absent scans remain supported for legacy queue records.
* Invalid published records stop worker inventory before relay. Invalid unpublished originals refuse new intake, even for an unrelated queue ID, until operator investigation.
* Rejection is read-only and does not expose mailbox addresses or original message bytes.
* Both integrity digests are recomputed in adversarial fixtures to prove semantic consistency is checked independently of checksums.
* No automatic mail replay, deletion, Postfix configuration mutation or running service restart.

## Qualification

Run `go test ./internal/transport -run 'TestQueueRejectsSignedScanEnvelopeMismatchBeforeRelay|TestQueueAllowsLegacyAbsentScanEnvelope|TestEnqueueRefusesSignedPendingScanEnvelopeMismatch' -count=1`, then full Go tests/race/vet and the existing disposable Postfix/Dovecot integration workflows. This document is not evidence of successful CI or real-host qualification; inspect exact-commit runs separately.

## Still open

Crash/power-loss and disk-full fault matrices, live ISPConfig mail-host validation, multi-recipient policy isolation, classifier false-positive measurements, browser acceptance and native backup/update/rollback. All nine production issues remain open until their acceptance gates pass.
