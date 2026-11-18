# Native backup source-directory validation — 2026-11-17

## Scope
The native cold-backup creator now validates each traversed directory path with the same portable filename guard used for archived files. Previously a nonportable *empty* directory (for example `CON`, `LPT¹`, a trailing-dot component, or an invisible format character) was silently ignored because only regular files were validated and written to the ZIP. An invalid nonempty directory could also be silently ignored if it contained only runtime lock files.

## Behavior
`backup.Create` refuses the source before archive publication with `unsafe data directory name`. It does not rename or remove source directories, alter the mail server, or relax the manifest/ZIP integrity checks. Linux-specific adversarial tests cover five invalid directory components and the absence of a published archive. A positive test creates and verifies a nested portable backup.

## Evidence and limits
These are source changes and committed regression tests, not production-host qualification. Existing exact-commit CI for prior HEAD `5f36d305682462f105f7adde7d6c41b92e2b8672` completed successfully: engineering run 44227236156 and disposable Postfix/Dovecot run 44227236168. Those runs do **not** validate this change. Current commit requires its own Go tests, CI and real cold restore verification.

This does not solve preservation of empty directories in ZIP backups; only regular files are restored. If an empty directory has application semantics, it must be represented explicitly in a future versioned archive format and covered by restore acceptance. Do not certify disaster recovery or close issue #8 on this change.
