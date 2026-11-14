# Rspamd HTTP scan result integrity — 2026-11-14

## Scope

The compatibility worker now rejects non-finite scanner scores, individual finding weights, active policy thresholds and scoring-trace thresholds **before** saving history or returning an MTA disposition. NaN and infinity cannot be represented by Go's JSON encoder. Previously, a non-finite value could reach history persistence and only fail during response encoding; the client might observe an incomplete successful HTTP response or retry an ambiguous scan.

The worker now returns HTTP 503 for an invalid scan result and does not call Store.Save for that result. This is a transport boundary, not proof that every upstream scoring configuration is finite or that all other Milter paths are protected. The validator intentionally does not modify scoring values or silently clamp them.

## Regression and qualification

The new unit tests cover normal finite values, positive/negative infinity, NaN, finding weights, configuration thresholds and scoring trace thresholds. The full repository must be compiled and tested at the exact final SHA. The isolated Postfix/Dovecot workflow is useful integration evidence but is not production ISPConfig or mail-host qualification.

Locked deployment architecture: native foreground launcher at /opt/spamgate/spamgate, spamgate-worker, persistent /opt/spamgate/data, and Postfix Milter ports 38470/38472. This change does not install, restart, or reconfigure any running MTA.

## Remaining acceptance

Issues #1–#9 remain open until independently verified. Real held-message release and mailbox placement, crash-safe delivery, SMTP/authentication conformance, classifier precision/false-positive cohorts, tenant policy isolation, diagnostics, complete browser acceptance, cold backup/restore and native upgrade/rollback remain mandatory.
