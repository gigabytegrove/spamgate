# Backup source pathname integrity — 2026-11-04

## Defect
The offline backup copied an already-open regular file and checked the descriptor after copying, but did not recheck the original pathname. A concurrent unlink or atomic replacement leaves the open descriptor readable, so the manifest could describe an inode no longer present in the source directory. A separate gap allowed an inode to change between initial Lstat and descriptor opening without comparing size, mtime, and Linux ctime at that stage.

## Correction
The backup creator now validates size, mtime and platform change-time when the descriptor is first opened, and rechecks the original pathname using Lstat after copying. A missing path, symlink, replacement inode or changed metadata aborts the backup before archive publication. The new helper is exercised by stable, replacement, unlink/symlink and mutation regression cases.

## Qualification boundaries
These checks are best effort, not an atomic filesystem snapshot. A privileged writer may still race between checks or alter a different file; stopping SpamGate and its writers remains mandatory for a consistent cold backup. Linux ctime is not a cryptographic integrity guarantee. No running mail server was changed. The test source is committed, but repository-wide Go tests and exact-HEAD CI must be independently inspected before treating the change as qualified.

## Locked deployment
Native Linux only; preserve /opt/spamgate/spamgate foreground launcher, spamgate-worker, /opt/spamgate/data and Postfix Milter ports 38470/38472. No Docker substitution and no automatic mail-host configuration changes.
