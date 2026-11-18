# Authenticated native backup inventories — 2026-11-18

Issue #8: add an opt-in HMAC-SHA256 authenticated manifest API to the existing read-only verifier.

- `SignManifest` signs the canonical validated version-1 manifest with a domain-separated HMAC.
- `AuthenticateManifest` compares authenticators in constant time before any backup file opens.
- `VerifyAuthenticated` checks the authenticator and then existing descriptor-safe file checks.
- `DecodeSignedManifest` refuses unknown JSON fields and trailing documents.
- The 32-byte minimum is a length check, not an entropy measurement. Keys must be random, kept separately from backups, and included in a separate disaster-recovery key escrow process.
- No automatic mail-server changes, Docker substitution, service restarts, or backup restore actions.

## Qualification boundaries

This is a library API, not yet integrated into a native backup command, UI, key manager or restore orchestrator. It does not establish snapshot consistency, inventory completeness, atomic recovery, authenticity of the signing operator, or a real-host restore. CI and mail-host evidence must be collected separately. Issues #1–#9 remain open until their full gates pass.
