# DMARC policy integrity pass — 2026-10-31

P0 authentication issue #3; no live Postfix/Dovecot changes and no new default rejection policy.

DMARC TXT records now distinguish DNS transport failure (`temperror`) from duplicate policy records (`permerror`). Candidate discovery detects duplicate `v` tags rather than allowing a later value to hide an otherwise present DMARC record. Policy parsing validates `v=DMARC1` first, required `p`, unique tags, nonempty values, and numeric `pct` within 0–100 before a policy can be used. Invalid inherited organizational-domain policy also returns `permerror`. Valid optional and unknown extension tags remain supported where syntactically valid.

Regression cases cover malformed tags, duplicate `v`/`p`, two DMARC TXT policies, invalid percentages, inherited policy, and temporary DNS failures. Verification must include `go test ./internal/core`, `go test ./...`, and exact-commit CI evidence.

**Remaining RFC gaps:** PSD DMARC, sampled enforcement for `pct` values below 100, aggregate/forensic reporting, full third-party fixture conformance, ARC trust policy, real Postfix authentication vectors, and production host validation. Do not call this RFC-complete or beta-qualified.

## RFC 9989 correction (2026-10-31)

RFC 9989 (May 2026) obsoletes RFC 7489 and RFC 9091. The prior pct validation and RFC 7489 sampling interpretation have been superseded: pct is historic and ignored. The current t=y test mode downgrades policy by one level; p is optional and defaults to none. Full RFC 9989 DNS Tree Walk, PSD and np handling remain open; the PSL fallback is not RFC 9989 conformance.
