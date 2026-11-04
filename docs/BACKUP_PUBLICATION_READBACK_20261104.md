# Backup publication readback gate — 2026-11-04

## Defect and correction
The offline backup writer previously closed and synced its temporary ZIP and immediately hard-linked it into the requested destination. Writer success does not independently establish that the on-disk ZIP can be reopened, that each compressed entry can be decoded, or that each entry matches its manifest digest.

`Create` now calls the existing `Verify` reader on the closed temporary archive before the no-overwrite hard-link publication. Verification checks ZIP structure, manifest completeness, per-entry sizes and SHA-256, archive bounds, and policy witness consistency. An error returns without publishing the requested destination; deferred cleanup removes the temporary file.

## Regression coverage
`TestCreatePublishesReadableVerifiedArchive` exercises create, reopen, manifest inspection and destination no-overwrite. `TestCreateDoesNotPublishInvalidSource` checks that a reserved manifest pathname cannot yield a published archive.

## Qualification limits
These tests are committed, not reported as executed in this pass. The gate does not create a filesystem snapshot, detect modifications after readback, or substitute for the offline worker lock. It does not prove cold restore, disk-failure durability, real mail-host recovery, or native upgrade/rollback. No production mail server was modified. Keep issues #1–#9 open until their acceptance evidence is complete.
