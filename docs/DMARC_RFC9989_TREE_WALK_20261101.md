# RFC 9989 bounded DMARC DNS Tree Walk (2026-11-01)

This change advances GitHub issue #3. It does **not** close protocol interoperability or live-host qualification.

## Behavior

* DMARC policy discovery walks the Author Domain toward the DNS root using at most eight queries per identifier when inheritance is required, skipping intermediate labels when the input is deep. A valid direct Author Domain policy is applied without unnecessary ancestor DNS lookups. It does not use the local public suffix list to select an enforcement domain.
* A `psd=n` record identifies the Organizational Domain; `psd=y` identifies the Public Suffix Domain, with the next lower label becoming the Organizational Domain. Without an explicit boundary, the least-specific discovered record establishes the Organizational Domain.
* Policy preference is Author Domain, Organizational Domain, then PSD. A subdomain inherits `sp` where present; direct Author Domain records use `p`.
* Relaxed SPF/DKIM alignment independently discovers each authenticated identifier's Organizational Domain, with shared per-message DNS caching and a 48-lookup amplification budget. Strict and identical-domain comparisons avoid unnecessary identifier DNS queries. An ancestor DNS outage cannot invalidate an already-discovered direct policy when no relaxed boundary lookup is required.
* Invalid `psd`, `np`, and `t` tag values fail with a non-enforceable policy error. DNS failures during alignment produce an inconclusive result rather than an authentication failure; a separate aligned DKIM signature can still pass.
* The native launcher, persistent data directory, Postfix listeners and existing deployment state are unchanged.

## Qualification limits

This is a targeted RFC 9989 discovery and alignment implementation, **not** full DMARC conformance. Conflicting policy TXT records at one DNS name are discarded per RFC 9989 section 4.10, and discovery continues to ancestors. Malformed individual records remain non-enforceable. Full `np` NXDOMAIN/NODATA differentiation, external reporting URI validation, cross-implementation fixture comparisons, live DNS interoperability, RFC 9990/9991 reporting, and real Postfix/Dovecot disposition remain open.

The resolver abstraction currently does not expose authoritative NXDOMAIN versus NODATA for the Author Domain, so this change deliberately does not apply `np` to unproven non-existent domains. Incorrectly treating missing `_dmarc` TXT as non-existent Author Domain would be unsafe.

Verification requires `go test ./internal/core ./internal/transport ./internal/server`, `go test -race ./...`, `go vet ./...`, exact-commit GitHub CI and isolated mail lab, followed by independent real-host evidence. No CI success is evidence of production-host acceptance.

References: RFC 9989 sections 4.10, 4.10.1 and 4.10.2 (https://www.rfc-editor.org/rfc/rfc9989).
