# Native executable promotion integrity — October 30, 2026

## Root cause

The supervisor checked the staged binary SHA-256 with `Pending()`, then
reopened the staged pathname without verifying the copied bytes against the
previously checked digest. Replacing the file after verification could install
unverified bytes. The old copy also followed source symlinks and did not fsync
the destination directory after the final rename.

## Fix

`pendingDetails()` binds the checked version and digest together.
`copyExecutableVerified()` checks the source identity, size, modification
time, and SHA-256 of the actual copied bytes before atomic publication.
Migration and rollback copies reject source symlinks and unsafe writable
destination directories. Published executables and their parent directories
are fsynced on Linux.

Tests cover same-size substitution, digest mismatch, symlink sources and
parents, malicious destination symlinks, replacement, and unsafe permissions.

## Still unqualified

The GitHub release's own SHA256SUMS file is not signed provenance. Real
power-loss recovery, real-host upgrade/rollback, live mail delivery, and all
remaining issues #1–#9 still require independent evidence. This change does
not touch the running mail server or alter the native launcher architecture.
