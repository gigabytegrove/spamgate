# PSL-aware visible-link phishing claims — 2026-11-01

## Scope and root cause

The opt-in `PHISHING_VISIBLE_LINK` classifier previously treated a host and
any suffix-related hostname as one trusted destination. This was incorrect for
private Public Suffix List boundaries (for example, distinct tenants under
`github.io` or `pages.dev`). It also flagged common legitimate links
between sibling hosts of one registrable organization.

The comparison now uses SpamGate's existing `organizationalDomain` PSL
implementation. Exact hosts match, and different hosts match only when both
resolve to the same nonempty organizational domain. A public suffix itself
is not an organization. The same bundled PSL and optional
`SPAMGATE_PUBLIC_SUFFIX_FILE` override used elsewhere remain authoritative.

## Security and behavior

- Distinct tenants under private public suffixes remain detectable.
- Ordinary sibling subdomains under one registrable domain do not receive
  a phishing mismatch score solely for changing hostnames.
- Unknown/unregistrable suffix-only hosts are never treated as an owner of
  child tenants.
- No DNS or remote reputation request is introduced.
- Existing opt-in configuration, score, finding symbol, MIME limits and
  coverage diagnostics are unchanged.
- No running Postfix, Dovecot, SMTP or Milter configuration is touched.

## Verification

`go test -count=1 ./internal/core` and `go test -race -count=1 ./...`
are required; the existing engineering CI runs full tests and vet.
The new regression matrix covers sibling hosts, multi-label public suffixes,
private tenant boundaries, MIME and classifier opt-in.

## Qualification boundary

A shared registrable domain is not proof that a URL is safe. A compromised
sibling host may still be malicious; this rule only avoids claiming that a
hostname difference alone proves impersonation. The PSL snapshot is dated
August 2024 and must be maintained for new private suffixes. This is
not a measured production false-positive rate or a replacement for a
third-party clean/spam corpus. Issue #5 remains open.
