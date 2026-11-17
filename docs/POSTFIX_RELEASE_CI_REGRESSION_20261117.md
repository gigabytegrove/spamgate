# Postfix HOLD release confidentiality regression — 2026-11-17

## Scope and evidence

Starting `main` HEAD: `69ad4d03992f96b2b30ca322f76b58a802a31d1f`.

The engineering qualification workflow [44020620638](https://github.com/gigabytegrove/spamgate/actions/runs/44020620638) failed at `go test -count=1 ./...` in `cmd/spamgate-postfix-release`. Five older subprocess tests expected raw child output or wrapped sink errors, contradicting the newer confidential reporting contract. The isolated Postfix/Dovecot laboratory workflow [44020620847](https://github.com/gigabytegrove/spamgate/actions/runs/44020620847) succeeded on that starting SHA, but is not production-host evidence.

## Corrections

`subprocess_linux_test.go` now expects a fixed successful confirmation, typed nonzero exit status without child stderr, and a generic reporting failure without forwarding sink error details. Short writes still fail, and failed child commands must not write success.

`subprocess_confidentiality_linux_test.go` adds independent tests for retained typed exit codes, confidential stdout and stderr on successful release, redaction of malicious result-sink errors, and no result write on child failure. Tests use temporary shell fixtures and do not change a mail server.

## Acceptance boundary

These tests verify the helper's reporting boundary, not whether a real Postfix queue entry was held, safely released, delivered to Dovecot, or recovered after restart. Real mail-host qualification is still required. This work does not change `/opt/spamgate/spamgate`, `spamgate-worker`, `/opt/spamgate/data`, Milter ports 38470/38472, or any running mail-host configuration.

GitHub issues #1–#9 remain open, including durable delivery, SMTP/authentication conformance, classifier false positives, tenant policies, diagnostics, browser operations, and native backup/update/rollback. No beta readiness is asserted. The October 31, 2026 target has passed.

## Verification record

Source changes committed to `main`. Final-HEAD engineering and isolated laboratory workflows were queued at documentation time. Do not treat pending, cancelled, or previous-HEAD workflow results as final-HEAD acceptance.
