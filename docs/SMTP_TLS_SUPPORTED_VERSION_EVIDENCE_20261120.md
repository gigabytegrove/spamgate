# SMTP TLS evidence integrity — 2026-11-20

## Scope
Issue #3 (SMTP protocol/authentication conformance) and issue #6 (diagnostic integrity). This is passive, read-only SMTP STARTTLS evidence handling. It does not authenticate, deliver mail, change Postfix or Dovecot, or certify production behavior.

## Implementation
The negotiated cipher suite is looked up in Go's crypto/tls supported and insecure cipher inventories. Its SupportedVersions is now checked against the observed TLS protocol version instead of inferring compatibility from a cipher name prefix. The assessment also identifies missing/unknown protocol version, missing leaf certificate metadata, missing or nonpositive verified-chain counts, and observed protocol versions older than TLS 1.2. Existing legacy-cipher, unknown-cipher and unexpected client-authentication findings are retained.

The new TLS evidence checks only execute when StartTLSVerified is true. A failed or skipped handshake must not produce a claimed negotiated-cipher verdict. These findings are diagnostics, not proof of SMTP AUTH, delivery, or certificate compliance across other clients.

## Regression coverage
- tls_version_matrix_test.go: compatible TLS 1.2/1.3, cross-version mismatches, TLS 1.0/1.1 evidence, missing and unknown versions, missing leaf metadata, missing/nonpositive verified-chain counts, missing suite, and unverified-handshake suppression.
- tls_assessment_integrity_test.go: full Assess propagation and failed-handshake suppression.

## Qualification
Source changes and tests committed to main through GitHub. Local full repository checkout was blocked by DNS resolution of github.com. New Go tests and full repository regression suite were not executed locally. GitHub Actions must be inspected for the final commit; an empty PR-filtered workflow result does not establish a pass. Real Postfix/Dovecot and production mail-host qualification was not performed.

## Outstanding acceptance
Issues #1–#9 remain production gates. This change is not a classifier, tenant-policy, queue-hold, backup/restore, browser UI, native updater or durable-delivery qualification. No beta readiness is claimed. Preserve /opt/spamgate/spamgate, spamgate-worker, /opt/spamgate/data, and Milter ports 38470/38472.
