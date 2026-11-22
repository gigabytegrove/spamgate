# Malformed historical SMTP recipient replay boundary — 2026-11-22

## Defect and correction

The outbound relay deduplicates persisted recipient lists before issuing downstream RCPT commands. Previous identity comparison used the final `@` separator; a malformed historical address such as `Alice@evil@EXAMPLE.ORG` could therefore be treated as equivalent to `Alice@evil@example.org` under ASCII domain folding. Malformed originals should not be canonicalized by deduplication.

The comparator now requires exactly one non-edge `@` separator in each address before comparing local parts byte-for-byte and DNS domains with ASCII-only case folding. Malformed records are equal only when their complete bytes are identical. The first accepted wire address and ordering remain unchanged. The bounded recipient-admission helper inherits the same rule.

## Regression coverage

`internal/transport/smtp_recipient_domain_case_test.go` exercises multiple separators, empty domains, exact malformed duplicates, replay ordering and capacity refusal. These are source-level tests and do not establish real SMTP host acceptance.

## Qualification and operational boundaries

Source commits are published on `main`. Full repository compilation and tests: **NOT EXECUTED** (owner-controlled builder unavailable; repository declares Go 1.27.4 while available local Go is 1.23.2). No GitHub Actions or other hosted CI was invoked. No production Postfix, Dovecot, ISPConfig, systemd service, or mail data was touched.

This is defense in depth, not an assertion that malformed records can pass the existing `validateRelayOriginal` preflight. Existing issues #1–#9 remain open. In particular, durable DATA acceptance failure injection, real Postfix HOLD and Sieve placement, classifier false-positive corpora, browser acceptance, and native rollback require independent end-to-end evidence before beta qualification. The original October 31 beta target has passed.
