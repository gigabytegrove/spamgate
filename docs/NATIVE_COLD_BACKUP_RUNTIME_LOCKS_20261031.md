# Native cold-backup runtime-lock isolation — 2026-10-31

Production gate: #8 (offline backup, restore and native recovery). No Postfix or Dovecot configuration is modified.

## Defect

The offline backup excluded only `.worker.lock`. It copied the independent native locks for history-journal serialization, Postfix HOLD release, SMTP intake and delivery. A cold restore by root could recreate those files as root-owned 0600 inodes, causing the unprivileged SpamGate worker to refuse startup, intake or queue processing even when the archive hashes and restore publication passed.

## Correction

New archives exclude only these exact ephemeral runtime paths:

- `.worker.lock`
- `.events-journal.lock`
- `.postfix-hold-release.lock`
- `delivery-queue/.delivery-worker.lock`
- `delivery-queue/.delivery-intake.lock`

The backup walk still inspects each entry before exclusion. A symlink, directory or other non-regular object disguised as a runtime lock fails the backup rather than disappearing silently. Forensic `.pending-*` originals, spool records, configuration, history, monitoring data and all other persistent files remain in scope.

Legacy archives are still integrity-verified **including the lock entries**, but restore does not recreate these runtime locks. New workers create their own private lock inodes. A legacy archive containing only lock files cannot publish an empty restore.

## Qualification limits

Unit tests cover new-archive exclusions, legacy-archive compatibility, preservation of unpublished originals, exact-name matching, unsafe masquerading locks and a full Create/Verify/Restore cycle. GitHub CI is not a substitute for a cold restore with real mail-host data, UID migration, ISPConfig and native systemd service restart. These gates remain open. Do not restore into an existing or running data directory.

## Backup destination symlink containment

A second cold-backup guard resolves the source and archive parent after directory creation, before opening a temporary ZIP. This rejects a destination whose apparent external pathname is actually a symlink alias into the data root. Without this check, a backup could read its own growing temporary ZIP during a recursive source walk. A symlink to a genuinely external directory remains supported. This is not a complete defense against a privileged adversary concurrently replacing parent-directory symlinks; offline backup still requires a controlled host and stopped worker.
