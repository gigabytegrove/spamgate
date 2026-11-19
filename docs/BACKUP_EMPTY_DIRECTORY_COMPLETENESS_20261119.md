# Native backup inventory completeness — 2026-11-19

## Defect and correction

Manifest version 1 enumerates regular files, not directories. Before this change, BuildInventory silently ignored empty directories. Consequently VerifyComplete could report a backup as complete even when an additional unlisted empty directory existed, and RestoreCold could publish a tree missing empty directories from the source. This is data loss disguised as successful verification.

BuildInventory now fails closed on empty directories, including nested empty directories. This behavior is inherited by CreateSignedInventory, VerifyComplete, and RestoreCold without altering the authenticated manifest wire format or adding an incompatible field. An operator must remove intentionally disposable empty directories from the quiesced snapshot before signing; do not remove active data.

Regression coverage: TestInventoryRejectsEmptyDirectories, TestVerifyCompleteRejectsNewEmptyDirectory, TestColdRestoreRefusesUnrepresentableBackupTree.

## Qualification boundaries

This is a narrowly scoped integrity correction, not a complete disaster-recovery implementation. Version 1 still does not preserve directory modes, ownership, ACLs, xattrs, sparse-file layout, hard links, database transactional consistency, or empty directories. The production backup workflow is not yet wired to the standalone backupverify package. Independent real-host cold-restore and native update/rollback evidence is still required.

Locked deployment: /opt/spamgate/spamgate foreground launcher, spamgate-worker, /opt/spamgate/data persistent, Milter 38470/38472; no Docker substitution and no running mail-server changes.

Issues #1-#9 remain open. The October 31 beta target passed; do not claim beta readiness from these commits. CI execution and real mail-host acceptance must be recorded separately from source inspection.
