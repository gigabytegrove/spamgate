# Portable backup path identity — 2026-11-17

Production gate: #8. This change rejects Windows device aliases (CON, PRN, AUX, NUL, COM1–COM9, LPT1–LPT9, CONIN$, CONOUT$), trailing-dot components, alternate-data-stream colons, and Windows-reserved filename punctuation in the shared backup path validator. The check is applied by archive creation, manifest decoding, ZIP inspection and restoration through existing safeName/canonicalBackupPath calls. It does not modify a running mail host.

Compatibility: older archives containing these paths are deliberately rejected. Recover those archives in a controlled isolated environment with the previous compatible build, rename the affected files offline, and create a new verified backup. No silent filename rewriting is permitted.

Evidence: source inspection and committed regression fixtures; no local Go test execution or real cold restore has been established by this document. Verify final-HEAD GitHub Actions separately. Real native systemd backup/restore and production-host qualification remain outstanding.
