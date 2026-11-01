# Native cold-restore readback verification — October 31, 2026

**Scope:** production gate #8 (offline recovery), with evidence integrity relevant to gates #1 and #2. This change does not claim a qualified disaster-recovery procedure.

## Behavior

The existing `-restore-backup` operation now rereads every extracted persistent file from the staging directory, validates its SHA-256 and byte count against the verified archive manifest, and rejects unlisted files, unexpected directories, symlinks, special files, and missing files **before** fsync and atomic no-replace publication. The earlier extraction-time SHA-256 check remains in place; the readback is an independent disk read. A failed check leaves the destination nonexistent and removes the staging directory.

A new read-only offline operation, `-verify-restored`, compares an existing restored directory with an independently validated backup archive. It checks file identity, size and modification time around each read. Only the exact known runtime flock paths are exempt from content comparison, and these must be regular files. This allows a worker to recreate its lock files without changing the persistent snapshot. The operation refuses a symlinked data root and on Linux obtains the same nonblocking `.worker.lock` as the native worker; it refuses an active worker holding that lock. It does **not** stop or restart any service.

The readback adds approximately one full read of the restored data to the offline restore process; it is intentionally not a background operation on the running mail host.

## Operator commands (manual, offline, never automatic)

Stop the native SpamGate service using the host's approved maintenance procedure, confirm all other writers are stopped, and create/verify an offline archive outside the data directory:

```bash
/opt/spamgate/spamgate-worker -data /opt/spamgate/data -backup-file /root/spamgate-cold.zip
/opt/spamgate/spamgate-worker -verify-backup /root/spamgate-cold.zip
```

Restore to a **new nonexistent** test directory, not the active data directory:

```bash
/opt/spamgate/spamgate-worker -data /root/spamgate-restore-drill -restore-backup /root/spamgate-cold.zip
/opt/spamgate/spamgate-worker -data /root/spamgate-restore-drill -verify-restored /root/spamgate-cold.zip
```

A zero exit status from the final command proves only that the files currently in the restored tree match the archive's manifest under the offline lock. The manifest contains hashes, **not an authenticity signature**. Preserve the archive and separate trustworthy checksums/attestations, and protect backup credentials and message contents.

## Verification and limitations

Automated regressions cover a clean roundtrip, legitimate runtime locks, same-size content tampering, missing and unexpected files, unexpected directories, symlink substitution, invalid archives, symlinked data root, runtime-only manifests, CLI operation conflicts, and CLI readback failure. Go unit/race tests and native builds run in the existing engineering CI. A green CI result is isolated test evidence, not production-host certification.

The worker lock is advisory: external tools that do not honor it can still modify files during verification. Same-size malicious rewrites that restore timestamps are not fully prevented without filesystem snapshots or coordinated writer suspension. No backup encryption, archive signing, crash/disk-full fault injection, real Postfix/Dovecot recovery, queue replay, actual host upgrade, or executable rollback has been qualified by this change. The permanent `/opt/spamgate/spamgate` launcher, `/opt/spamgate/spamgate-worker`, `/opt/spamgate/data`, and ports `38470`/`38472` remain unchanged.
