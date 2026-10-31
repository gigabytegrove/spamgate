# RFC 9989 DMARC test mode and historic pct — 2026-10-31

Source: https://www.rfc-editor.org/rfc/rfc9989.html (May 2026, Standards Track; obsoletes RFC 7489 and RFC 9091).

Issues #3 and #5: This change corrects a previous legacy-RFC implementation. The pct tag is historic and MUST NOT change current policy handling. The t tag replaces testing semantics: t=y lowers reject to quarantine, and quarantine to none; t=n or absent retains the published policy. The DMARC authentication result remains fail. p is optional and defaults to none. The v=DMARC1 value is case sensitive and must appear first.

The scanner preserves the original policy, effective scoring policy, and test-mode state in the DMARC_FAIL evidence and adds a scan-trace entry for t=y. This remains scoring (+6 reject, +4 quarantine, +0 none), not direct DMARC SMTP enforcement. Other local findings or explicit administrative overrides can still reject mail.

Regression tests cover t=y/t=n, missing p, obsolete pct values including pct=0, version syntax, and scanner scoring. The first commit in this pass applied obsolete RFC 7489 pct sampling; this commit supersedes it after checking the published May 2026 standard. Do not deploy the superseded intermediate commit.

Remaining production gaps: RFC 9989 bounded DNS Tree Walk, PSD and np handling, domain-existence checks, alignment via DNS Tree Walk, invalid-tag default semantics, aggregate/failure reporting (RFC 9990/9991), third-party conformance, real mail-host qualification, and all cumulative issues #1–#9.
