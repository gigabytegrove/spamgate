# SMTP TLS evidence independence — 2026-11-20

## Scope and verified source
Starting main HEAD: c20839d8bc77a0d0b6b906505b3a09821fa60316. Read internal/smtpprobe/tls_evidence.go, assessment.go, probe.go, tls_version_matrix_test.go, go.mod and open issues #1–#9 before modifying code.

## Root cause and correction
Previously, TLS_VERSION_EVIDENCE_UNKNOWN and TLS_OBSOLETE_VERSION_NEGOTIATED were emitted only from the branch that recognized a nonempty cipher suite. Missing or unrecognized cipher evidence therefore suppressed independent protocol findings. The version parser now runs before cipher classification and reports version defects independently, while the compatibility mismatch still requires a recognized suite and recognized version.

The diagnostic now also checks certificate validity timestamp presence, strictly increasing NotBefore/NotAfter, and invalid expiry-day values less than -1. These are consistency findings about stored observations, not assertions about the live host or proof of certificate verification.

## Regression coverage
New tls_independent_evidence_test.go covers seven version/cipher combinations, seven certificate validity scenarios, and suppression for unverified handshakes. The existing version matrix and assessment tests remain in place.

## Verification boundary
Changes were published through the GitHub connector. GitHub checkout from the execution host failed DNS resolution of github.com; installed Go is 1.23.2 while go.mod requires 1.27.4. No full repository compilation or Go regression execution is claimed. At the final test commit, combined status returned no status entries and the commit workflow lookup returned no PR-triggered runs; this lookup cannot certify push CI. No Postfix/Dovecot host was accessed.

## Open acceptance
All issues #1–#9 remain open: live Postfix/Dovecot final disposition and hold/release, durable accepted-original delivery, independent SMTP/authentication protocol conformance, classifier false-positive calibration, tenant-policy enforcement, retained operational diagnostics, browser acceptance, cold backup/restore and native update/rollback. This pass is a narrow diagnostic correctness fix and does not satisfy the required multi-subsystem production engineering scope.

Locked architecture unchanged: foreground /opt/spamgate/spamgate, spamgate-worker, persistent /opt/spamgate/data, Milter ports 38470/38472. No Docker substitution or automatic mail-host changes. October 31 beta target has passed; beta is not qualified.
