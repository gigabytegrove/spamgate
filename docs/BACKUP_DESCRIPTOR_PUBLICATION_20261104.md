# Linux descriptor-relative backup publication — 2026-11-04

The prior pathname-based os.Link operation had a race after destination-parent validation: a concurrent directory replacement could redirect publication. Linux now opens the parent with O_DIRECTORY|O_NOFOLLOW, verifies the directory inode against the captured identity, and invokes linkat with both names relative to the same directory descriptor. Link creation retains no-overwrite semantics. Other platforms retain the existing behavior.

Regression coverage: normal publication, existing destination, replaced parent, symlink parent. Remaining limitation: parent directories above the final component can be redirected before the descriptor is opened; the inode comparison rejects mismatches. An adversary replacing the directory after the descriptor is opened can detach the published archive from its expected pathname; the operation cannot be redirected into the replacement directory. Backup remains offline-only and does not provide a filesystem snapshot.

This is not production-host disaster-recovery qualification. Full native Linux, mail-host and cold restore gates remain open.
