# Native backup inventory and isolation — 2026-11-18

Scope: issue #8, read-only native backup verification. The permanent foreground launcher remains /opt/spamgate/spamgate, the worker remains spamgate-worker, persistent data remains /opt/spamgate/data, and Postfix Milter ports remain 38470/38472. No Docker substitution or running mail server changes.

## Implemented
- BuildInventory inventories a pre-existing, quiesced backup tree in sorted path order; hashes every file using the hardened descriptor-relative opener, rejects symlinks and nonregular files, and enforces file-count and size bounds.
- CreateSignedInventory authenticates that inventory with the existing HMAC-SHA256 manifest format and a separately held key.
- VerifyComplete authenticates before filesystem access, rejects missing, extra, modified or substituted files, then reopens and verifies the signed inventory.
- CheckBackupBoundary refuses identical, nested, or symlink-aliased active-data and backup directories; this is a guard for a future operator-facing workflow, not an automatic invocation.
- Regression tests cover valid signed inventories, added/deleted files, invalid keys, symlink entries and roots, empty trees, nested/aliased paths and sibling paths.

## Evidence and qualification gaps
Starting main HEAD: ca7c5f534d36e29d6f31ba8dac05a36194370217. These changes were committed directly to main through GitHub. A local git checkout failed because github.com DNS resolution was unavailable; installed Go 1.23.2 is older than the module's Go 1.27.4 requirement. No local test success is claimed. GitHub commit workflow lookup filters to pull-request runs and cannot certify push CI. Verify final-HEAD CI separately.

The inventory is not an atomic snapshot. Concurrent writers, directory substitution during discovery, changed inode content after reading, or a mutable backup source can invalidate its completeness guarantee. Use only on an immutable, quiesced tree. This does not yet implement snapshot creation, backup scheduling, cold restore, permission/ownership recovery, secret escrow, native update/rollback, or live mail-host qualification. Issues #1–#9 remain production gates. October 31 beta deadline has passed; SpamGate is NOT beta-qualified.
