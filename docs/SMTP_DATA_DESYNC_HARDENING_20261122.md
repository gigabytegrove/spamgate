# SMTP DATA desynchronization hardening — 2026-11-22

## Defect and scope
The SMTP handler returned 552 after an oversized DATA read, reset the envelope and resumed parsing commands on the same socket. An over-limit read does not establish whether the remaining bytes have been drained to the terminating dot line. If bytes remain, attacker-controlled message body lines can be interpreted as new SMTP commands. This is a protocol state-desynchronization risk even when the client is restricted to trusted network ranges.

## Correction
All errors returned by readSMTPData now terminate the SMTP session after a single reply. The over-limit response remains 552 5.3.4; other DATA read failures return 554 5.6.0. A successful DATA read continues through the existing wire, contract, scanner and durable-queue gates unchanged. The handler never acknowledges a failed DATA read with 250. The error mapper has regression cases for direct/wrapped size errors and other failures.

## Qualification
Source changes committed to main. The complete repository build, unit tests, SMTP socket integration tests, failure injection, and real Postfix/Dovecot tests were NOT EXECUTED in this pass because the owner-controlled build host was unavailable and the local checkout could not resolve github.com. The regression tests are committed but not claimed passing. GitHub Actions are prohibited and were not used.

## Remaining production gates
This is a targeted protocol-safety fix, not a claim that the long-term beta is ready. Issues #1–#9 remain subject to cumulative qualification, including Postfix/Dovecot holds, durable queue recovery, SMTP interoperability, classifier accuracy, tenant policies, diagnostics, browser UI, backup/restore, and native update/rollback. The native Linux launcher, worker, data directory and Milter ports are unchanged.
