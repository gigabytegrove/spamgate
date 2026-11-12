# SMTP EHLO capability consistency evidence — 2026-11-12

Scope: read-only SMTP relay diagnostics (GitHub issues #3 and #6). The probe sends EHLO and QUIT, with STARTTLS and a second EHLO only when TLS mode requires it. It never sends AUTH, MAIL FROM, RCPT TO, DATA, or BDAT.

The `capability_warnings` JSON array is sorted and contains stable machine-readable identifiers for duplicate EHLO extensions, malformed extension keywords, unexpected parameters on parameterless extensions, and BINARYMIME advertised without CHUNKING. Warnings are based on the final EHLO after STARTTLS when TLS is required. An empty array means no listed inconsistency was observed, **not** that the relay passed SMTP protocol conformance.

Regression coverage: clean EHLO, identity-line exclusion, duplicate extensions, malformed keywords, illegal parameters, BINARYMIME/CHUNKING dependency, deterministic warning ordering, and an isolated TCP SMTP peer asserting no authentication or mail submission commands. No production server is modified.

Qualification still required: exact-HEAD engineering CI, isolated Postfix/Dovecot laboratory, real mail-host transaction and hold/disposition evidence, TLS/auth interoperability, durable delivery, false-positive corpus, tenant-policy isolation, browser workflows, backup/restore, and native update/rollback. No beta readiness claim follows from these diagnostics.
