# SMTP recipient DNS-domain identity correction — 2026-11-22

Scope: production issues #1, #2 and #3. The SMTP local part is preserved exactly and compared case-sensitively. The DNS domain is compared case-insensitively, consistent with domain-name semantics. The original first accepted recipient string is retained without rewriting.

## Defect
Previously, `Alice@EXAMPLE.ORG` and `Alice@example.org` consumed two of the 100 recipient slots and produced two downstream RCPT commands. These strings identify the same domain and local part, so the duplication could create an unnecessary second delivery. This also allowed duplicate domain-case variants to exhaust the distinct-recipient cap.

## Implementation
- `sameSMTPRecipient` compares local parts byte-for-byte and domains with `strings.EqualFold`.
- Malformed historical recipient strings are compared only as exact byte strings, not normalized into valid identities.
- `acceptSMTPRecipient` remains idempotent at the capacity boundary and refuses new recipients without changing the accepted envelope.
- `uniqueSMTPRecipients` preserves the first accepted wire address, recipient order, plus tags and local-part case.
- Ingress and outbound relay both use the shared identity helper.

## Regression coverage
- Local-part case and plus-address distinctions.
- DNS-domain case equivalence, symmetry and different domains.
- Malformed historical strings without silent normalization.
- Capacity behavior at the two-recipient test limit.
- Replay preserving the first wire address.
- Loopback SMTP relay with mixed-domain-case duplicate RCPT addresses.

## Qualification limits
GitHub commit publication is not execution evidence. These tests and the full engineering/isolated mail-lab workflows require independent successful runs at final HEAD. Real Postfix/Dovecot placement, crash recovery, ambiguous DATA acceptance, tenant policies, classifier precision/false positives, browser acceptance, cold restore, and native upgrade/rollback remain open. No production host was touched, and the native Linux launcher, worker, persistent data path and Milter ports remain unchanged.
