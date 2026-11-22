# SMTP recipient allowlist ASCII DNS authorization — 2026-11-22

## Change
The SMTP ingress recipient-domain allowlist now compares DNS domain bytes with ASCII-only case folding using the same identity semantics as envelope deduplication. A Unicode character such as U+212A (Kelvin sign) must not be converted to ASCII `k` by Go Unicode `strings.ToLower` and then treated as an authorized domain. Preserve the first accepted wire recipient and the case-sensitive local part.

## Regression
`TestSMTPRecipientAllowlistUsesASCIIDNSCase` covers ASCII mixed-case equivalence, Unicode lookalikes, suffix spoofing, trailing dot, and malformed addresses. `TestSMTPRecipientAllowlistDoesNotChangeEnvelopeIdentity` verifies deduplication retains the original wire address.

## Qualification boundaries
These tests are source regressions, not evidence of production-host SMTP qualification. The parser remains responsible for valid envelope syntax and IDNA normalization. Do not alter running Postfix/Dovecot configuration or assert beta readiness on this basis.

## Outstanding acceptance
Issues #1–#9 remain open: Postfix/Dovecot holds and disposition, crash-safe delivery, SMTP/auth interoperability, classifier precision and false positives, tenant policy conflict resolution, retained diagnostics, browser acceptance, backup/restore, native update and rollback. Require full Go regression/race/vet, independent isolated mail lab and real-host evidence before closure.
