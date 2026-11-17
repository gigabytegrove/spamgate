# Backup filename portability hardening — 2026-11-17

## Implementation
Backup manifest validation, source archive creation, and ZIP inspection now share a canonical filename guard. Invalid UTF-8, Unicode format/control characters (including bidi overrides and zero-width joiners), and Unicode whitespace are refused. The existing traversal, symlink, size, hash, ordering, and file/directory collision checks remain in force.

## Compatibility
Existing archives containing such filenames now fail verification rather than silently restoring ambiguous paths. Operators must rename affected files on a stopped, offline data tree and create a new backup. No automatic migration or running mail-host change is performed.

## Evidence and limits
Source commits were pushed to main. Regression fixtures cover malformed UTF-8, bidi overrides, zero-width joiners, nonbreaking and ideographic spaces, and control characters. Local checkout is blocked by GitHub DNS resolution; local Go is 1.23.2, below the repository requirement. Regression execution, final-HEAD push-triggered CI, real cold restore, and production mail-host acceptance are **not verified**.

Issues #1–#9 remain open. The October 31 beta target has passed. This is a bounded backup hardening change, not beta qualification.
