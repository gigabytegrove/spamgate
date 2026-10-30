# Native SpamGate offline backup and restore qualification

This document covers the native Linux layout only. The installed foreground launcher remains `/opt/spamgate/spamgate`, the worker remains `/opt/spamgate/spamgate-worker`, and persistent state remains `/opt/spamgate/data`. No backup command changes Postfix or its `milter_default_action = accept` policy.

## Snapshot consistency

The Linux offline backup path now acquires an exclusive, nonblocking advisory `flock` on `/opt/spamgate/data/.worker.lock` for the full backup, including publication. An active worker holding that lock causes backup creation to **fail**. Do not defeat the check by deleting the lock file while the worker is running: replacing the inode defeats advisory lock coordination.

The lock is not a snapshot transaction. All other writers to `/opt/spamgate/data` must be stopped as well. For example, external maintenance tasks and manual edits do not necessarily honor this lock. File identity, size, and modification time are checked before and after copying; same-size in-place edits with deliberately restored timestamps cannot be ruled out without a filesystem snapshot or coordinated application pause.

The runtime lock file itself is omitted from the archive. Backup archives and restores reject symlinks and nonregular file entries, reject empty or inconsistent manifests, verify per-file SHA-256, and refuse overwrite of an existing destination. On non-Linux platforms the worker-lock interlock is not implemented; stop all writers manually.

## Read-only preparation on the mail host

```bash
ps -eo pid,etime,args | grep -E '[s]pamgate|[p]ostfix'
ls -ld /opt/spamgate/data
ls -l /opt/spamgate/data/.worker.lock
```

The backup procedure is **offline**. Arrange a maintenance window and stop the native launcher through the service mechanism already used on that host. Do not blindly run `pkill` or modify Postfix. Once the launcher and worker have stopped, use the installed worker executable's documented offline CLI:

```bash
/opt/spamgate/spamgate-worker -data /opt/spamgate/data -backup-file /root/spamgate-offline-20261030.zip
/opt/spamgate/spamgate-worker -verify-backup /root/spamgate-offline-20261030.zip
```

Never run these commands as an automatic action on the production mail host. The backup contains potentially sensitive configuration, event history, and message evidence. Keep its file permissions at 0600 and store it securely off-host.

## Isolated restore rehearsal

Restore to a **new, nonexistent directory**, not the live data path:

```bash
/opt/spamgate/spamgate-worker -restore-backup /root/spamgate-offline-20261030.zip -data /root/spamgate-restore-drill
```

Compare the verified manifest with the restored tree, then run a disposable native/Postfix/Dovecot integration exercise against the restored configuration on a separate host. Only a completed test with queue IDs, recipient mapping, and mailbox outcomes qualifies recovery. A successful archive verification alone is not disaster-recovery certification.

## Evidence still required

- Reproducible crash and disk-full injection during archive creation, fsync, and publication.
- A live-host worker-lock refusal test against the exact installed revision.
- Full restore and requalification with actual Postfix/Dovecot, including queue holds and Junk placement.
- Upgrade-to-newer, rollback-to-previous, and configuration migration across a cold restore.
- Windows backup lock equivalence; Linux-only locking is not a cross-platform guarantee.
