# SMTP allowlist normalization boundary — 2026-11-22

## Defect and impact

The native SMTP environment constructor previously called `strings.ToLower` on configured recipient-domain names *before* DNS syntax validation. Go's Unicode case conversion can turn U+212A (Kelvin sign) into ASCII `k`. Consequently, a malformed Unicode configuration entry could be accepted as a different ASCII allowlisted domain. The listener preflight could not detect the original unsafe spelling after this transformation.

## Change

Validate the original trimmed domain using the existing ASCII-only DNS check and recipient-domain syntax validator before lowercasing. Preserve uppercase ASCII configuration compatibility and canonical lowercase storage. A single invalid comma-separated entry rejects the entire listener configuration; it cannot silently enable partial authorization.

Regression tests cover ordinary uppercase and mixed-case DNS names, Unicode Kelvin sign in initial and later labels, dotted I, fullwidth characters, invalid entries after commas, trailing empty entries, and constructor fail-closed behavior.

## Qualification and boundaries

Commits are source-control evidence only. Go compilation, full regression/race suite, isolated native Linux build, SHA-256 build provenance, and real Postfix/Dovecot acceptance are **NOT EXECUTED** in this pass. No GitHub Actions were used. No mail-host configuration, running process, systemd unit, native launcher, worker, persistent data directory, or Milter port was modified.

This is a targeted security correction, not completion of production issues #1–#9. The 2026-10-31 beta deadline has passed. Remaining gates include durable delivery crash/retry ambiguity, actual Postfix hold and Dovecot disposition, authentication and classifier false-positive evidence, tenant policies, diagnostics, browser acceptance, cold backup/restore, and native update/rollback. The next owner-controlled qualification must pin the exact HEAD, execute the complete test suite and record raw logs and checksums before any beta-ready claim.
