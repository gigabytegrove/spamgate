# Backup manifest acceptance hardening — 2026-11-17

Starting main: fc936b7463f3d11242e9c24e4050314e3e555fcf.

## Implementation
Version-one offline ZIP manifests are now rejected during manifest decoding unless they identify format 1 and product SpamGate, contain 1–100000 files, use strictly ascending unique canonical relative paths, and describe nonnegative payload sizes whose aggregate does not exceed 16 GiB. SHA-256 evidence must remain exactly 64 lowercase hexadecimal characters. The existing archive reader separately checks archive topology, actual decompressed sizes, hashes, runtime-lock exclusions and policy witnesses.

These checks happen before restore publication. Native backup creation already sorts manifest entries, so valid archives created by SpamGate preserve the new ordering contract. This does not migrate or rewrite any existing archive, and does not change the running Postfix/Dovecot server.

## Verification boundaries
New unit cases exercise version/product identity, duplicates, ordering, traversal, reserved names, controls, negative sizes and aggregate overflow. Passing compilation and CI must be independently confirmed on the final commit. A disposable CI mail lab is not a real ISPConfig production host. No actual production backup/restore, privileged Postfix operation, mailbox placement or update rollback has been qualified here.

## Outstanding gates
GitHub issues #1–#9 remain open pending live evidence and cumulative engineering: delivery and crash recovery, SMTP/authentication, classifier false-positive measurement, tenant policies, diagnostics, full browser acceptance, backup/restore and native updater rollback, and Postfix/Dovecot disposition. Never mark beta qualified on these source changes alone.
