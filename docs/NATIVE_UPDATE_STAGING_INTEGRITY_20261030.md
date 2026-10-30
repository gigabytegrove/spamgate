# Native update staging: metadata integrity and filesystem safety (2026-10-30)

Issue #8: this change hardens the existing single-host native launcher/worker update workflow. It does **not** change the foreground launcher at /opt/spamgate/spamgate, the worker name, persistent /opt/spamgate/data, or Postfix configuration.

## Failure fixed

Previously Stage wrote updates/pending.json with os.WriteFile. A pre-existing pending.json symlink could redirect that write to another worker-accessible file, including config.json. A crash during the truncate/write also left partially written metadata. Pending read that metadata without a byte limit and followed symlinks for both the manifest and staged executable. Record similarly wrote update state through a temporary rename but did not sync the containing directory.

## New behavior

- Updates must be in a real directory that is not group/world-writable; symlinked or unsafe update directories are refused.
- Staged binary and pending.json are each written to a private temporary file, fsynced, and atomically renamed into place. On Linux the containing directory is fsynced after each publication.
- A destination symlink is replaced, not followed. Pending refuses symlinked metadata and binary paths and compares opened file identity to Lstat.
- Pending bounds metadata to 4096 bytes and checks for mutation while reading/hash-verifying.
- Last-update records use the same atomic publication and bounded read path. An absent record remains a normal no-record result.
- Publication order remains binary first, metadata second. A crash between these two operations can leave an unmatched pair; Pending rejects the pair and does not install it. Operators can stage again. This is fail-safe, not an automatic crash-recovery claim.

## Qualification still required

This is filesystem and regression-test hardening, not proof of production host installation, successful restart, cold restore, power-loss behavior, or real mail disposition. Real systemd deployment and native upgrade/rollback must still be tested on the actual mail host. Never automatically modify the running Postfix configuration. Do not close issue #8 solely on this patch.
