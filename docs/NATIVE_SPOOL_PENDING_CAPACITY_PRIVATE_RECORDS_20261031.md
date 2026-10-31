# Native SMTP spool: unpublished capacity and private-record enforcement

Engineering scope: native Linux `main`, October 31, 2026. No production mail server changed.

## Root causes and correction

Previously SMTP intake capacity counted published jobs only, omitting fully synced
`.pending-*` originals retained after interrupted publication. Pending originals
can be the only surviving forensic copy, so both their count and apparent bytes
now reserve capacity against the existing 500-job / 512-MiB bounds. Full
capacity returns SMTP temporary refusal rather than unreserved acceptance.

Published reads previously checked inode identity and size but not Linux
ownership, private permissions or hardlink count. Both published and pending
originals now require worker ownership, owner-readable private regular files
and exactly one link. Atomic publication refuses unsafe existing destinations
and preserves the synced temporary evidence rather than replacing an
unexpected symlink or hardlink.

## Verification and limitations

New Linux regressions exercise pending count and byte saturation, hardlinked
published and pending originals, exposed originals, repair/resumption, and
symlink replacement refusal. Exact-commit Go/race/CI and isolated
Postfix/Dovecot runs are separately required.

These tests do not simulate actual ENOSPC, physical power loss, fsync faults,
live mail-host disposition, or native upgrade/rollback. Pending originals are
never silently replayed, deleted, or claimed delivered. The SMTP 250/crash
window remains at-least-once, potentially duplicating mail. Linux-specific
ownership checks are not claimed for Windows.

Preserved: permanent foreground `/opt/spamgate/spamgate`, worker
`spamgate-worker`, persistent `/opt/spamgate/data`, Milter ports 38470/38472,
native deployment and unchanged production Postfix fail-open policy.
