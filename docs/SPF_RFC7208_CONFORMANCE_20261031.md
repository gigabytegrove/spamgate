# SPF RFC 7208 safety and interoperability pass — 2026-10-31

Scope: P0 authentication/protocol issue #3. This change does not enable new enforcement defaults or modify a live mail server.

- An include whose target has no SPF record is now a **permerror**, not a match miss that can fall through to an unrelated `-all`. A redirect to a target with no SPF record is likewise a permerror.
- Record mechanisms and known modifier multiplicity are checked **before** a permissive mechanism can match. Unknown valid modifiers are ignored per RFC 7208. Unsupported SPF macros and deprecated PTR remain explicit permerrors rather than fabricated authorization.
- SPF `a`/`mx` now parse the full dual-CIDR form `/24//64`; invalid prefixes are rejected even if the DNS RRset is empty.
- SPF `exists` only matches when the A RRset contains an IPv4 address. AAAA-only responses do not pass.
- NXDOMAIN responses for TXT, A/AAAA and MX count toward the RFC void-lookup budget. A missing MX RRset falls through to later mechanisms rather than yielding a premature `none`.
- Tests cover the cases above, including malformed terms after `+all`, duplicate modifiers, and upper-case mechanism names.

Qualification: `go test ./internal/core` and `go test ./...` plus the repository's isolated Postfix/Dovecot CI are required. A green unit test does **not** establish full RFC 7208 compliance, live mail-host behavior, SPF macro support, or DMARC/ARC interoperability. Do not close #3 on this change alone.
