# Native backup manifest v2 — directory-complete restore (2026-11-19)

Starting HEAD: 3c8ab87d87e9bb45aa4cb80d50e4d8e1eea733cd.

Manifest v1 could not represent empty directories. This pass introduces version 2 with an authenticated, sorted directory inventory. BuildInventory now produces v2; the verifier compares the entire directory inventory and the cold restore creates all authenticated directories, including empty ones. Legacy v1 manifests remain readable, but v1 never claims to represent empty directories. A v2 manifest requires explicit parent directories and refuses collisions, duplicates and traversal. HMAC covers the new directory field through canonical JSON serialization.

Tests added for nested empty-directory restoration, unexpected directory detection, tampered directory inventory and collisions.

**Qualification boundaries:** Source checkout compilation and real-host restore remain unverified until CI and host evidence. File and directory ownership, ACLs, xattrs, snapshot consistency, update/rollback and production mail-host acceptance remain outstanding. No running mail service changes.
