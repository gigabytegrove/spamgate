# RFC 9989 non-existent subdomain policy safety — 2026-11-01

## Scope and observed defect

Prior runtime parsed `np=` but never selected it. For an inherited policy
`p=none; sp=none; np=reject`, an invented Author Domain was treated like an
existing subdomain. Conversely, inferring nonexistence from a missing
`_dmarc.<author>` TXT lookup would incorrectly reject legitimate existing
domains with no DMARC TXT record.

RFC 9989 §3.2.13 defines nonexistence by **NXDOMAIN** for the Author Domain,
not a missing record of one RR type. RFC 9989 §4.7 applies `np` only to
non-existent subdomains; `sp` (or `p`) governs existing subdomains.

## Implemented

- The inherited policy is selected using an exact Author Domain NXDOMAIN
  result when `np` differs from the ordinary inherited policy.
- `DMARCNameStatusResolver` is a narrowly scoped optional DNS response-code
  contract. Its `DMARCNameNXDOMAIN` method must return true only for
  NXDOMAIN, false for NOERROR (including NODATA), and an error for ambiguous
  or transient DNS responses. It receives the bounded DMARC context.
- If that capability is unavailable, the authentication result is
  `temperror`, the actionable `Policy` is cleared, and the reason is
  explicit. **Do not convert this into an actionable reject.**
- Direct Author Domain policies, aligned passes, authentication temporary
  errors and equivalent `sp`/`np` policies do not require an additional
  status query. `t=y` still downgrades the selected `np` policy.
- No new service, privileged helper, Docker runtime or mail-server changes.

## Remaining blocker and qualification

The default `net.Resolver` and existing `SPFResolver` expose no DNS
RCODE for an arbitrary Author Domain. This change intentionally does **not**
pretend that `LookupTXT`, `LookupIPAddr` or `LookupMX` returning
`net.DNSError.IsNotFound` distinguishes NXDOMAIN from NODATA. Production
`np` enforcement remains blocked until a bounded DNS RCODE-capable backend
is integrated and independently verified against NXDOMAIN, NOERROR/NODATA,
wildcards, SERVFAIL, timeouts and DNSSEC denial variants. That is a
**production gate #3 blocker**, not a beta acceptance claim.

Tests cover existing/nonexistent names, resolver absence, SERVFAIL, direct
policy, authentication pass/tempfail, equivalent dispositions and test mode.
They are deterministic stub DNS tests, not third-party DNS interoperability.

Reference: https://www.rfc-editor.org/rfc/rfc9989.html
