# SMTP AUTH evidence regression repair — 2026-11-13

## Source and observed failure
The engineering qualification run for commit `193d68db01d81efe323561a5ce476e025ec905ac` failed during `go test -count=1 ./...` in `internal/smtpprobe`. The failing subtest was `TestCapabilitiesEvidenceBoundaries/single_AUTH_advertisement_deduplicated`: it expected PLAIN and LOGIN from `AUTH PLAIN plain LOGIN`, but the fail-closed parser returned no mechanisms. This is an outdated expectation, not evidence that a real SMTP server failed.

## Changes
The legacy test now expects rejection of repeated case-insensitive AUTH mechanisms. A separate cross-check regression verifies agreement between the AUTH trust predicate, capability extraction and structured warnings for ordinary, legacy, duplicate, multi-line, empty and identity-only advertisements.

## Qualification boundary
This change is diagnostic-only. It does not attempt authentication, submit credentials, configure Postfix or Dovecot, change Milter listeners, or modify a live mail host. The locked native paths and Milter ports are unchanged.

## Evidence required
Run exact-HEAD `go test -count=1 ./...`, race tests and `go vet ./...` in engineering CI. Check the isolated Postfix/Dovecot laboratory independently. Neither isolated CI nor unit tests substitute for production mail-host acceptance. Production issues #1-#9 remain open pending their own gates.
