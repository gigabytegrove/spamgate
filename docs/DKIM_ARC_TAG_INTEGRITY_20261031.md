# DKIM/ARC tag integrity hardening — 2026-10-31

Scope: GitHub P0 authentication issue #3. Native Linux architecture, Milter ports,
Postfix configuration and running mail server remain untouched.

## Implemented

- Reject duplicate or malformed DKIM signature tags rather than letting the
  last value silently overwrite an earlier authenticated identity, selector,
  hash or signature. Validate mandatory tags and DKIM v=1.
- Reject DKIM identity outside the signing domain, invalid signing/expiration
  timestamps and expiration preceding signing time, and canonicalization tags
  with extra components. Require an actual signed From header.
- Reject duplicate/malformed DNS key tags, non-first key version tags,
  key records that disallow SHA-256, and service restrictions that exclude
  email. Preserve valid RSA/Ed25519 keys and optional extensions.
- Validate ARC-Message-Signature and ARC-Seal tag uniqueness during
  structural inspection. Parse ARC-Authentication-Results separately because
  its authserv-id and method results are not a DKIM tag list. ARC structure
  remains explicitly untrusted until cryptographic validation succeeds.

## Qualification and limitations

Run gofmt, go test ./internal/core, go test ./..., go test -race ./internal/core,
go vet ./..., and exact-commit engineering and Postfix/Dovecot lab CI.
This is not evidence of live mail-host behavior or complete RFC 6376/8617
interoperability. Remaining gates include third-party signed corpus vectors,
ARC forwarding and key rotation, PSD DMARC, tenant enforcement, durable delivery
fault injection, browser qualification, update/rollback and real host tests.
Do not close #3 or declare long-term beta ready from this change.
