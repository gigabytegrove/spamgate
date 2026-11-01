# Native updater executable-identity probe hardening — 2026-11-01

## Scope and root cause

The integrated native supervisor previously used exec.CommandContext(...).Output() for -version and -build-version. Output() buffered untrusted worker stdout without a size limit. The build probe also interpreted every execution failure as a legacy unsupported flag, including timeouts, missing files and launch failures. This could make a broken candidate appear unversioned during migration and weaken release identity checks.

## Implemented

Both source and build identity probes now have a five-second process deadline, one-second descendant-pipe wait limit, and a 4,096-byte stdout ceiling. Stderr is discarded, never collected. Only a normal exit with empty stdout (including nonzero unsupported-flag exits) is compatible with pre-numbering workers. A failed command that emits a contradictory build identity, a timeout, an abnormal exit, missing executable, excessive output, or a malformed explicit ID is rejected. Existing legitimate empty-output legacy compatibility is preserved.

## Qualification boundary

The probes do not cryptographically authenticate executables. Existing staged artifact SHA-256 verification, release identity validation, executable permissions, supervisor rollback and separate host qualification remain required. This is an offline regression fix; it does not install, restart, or alter any production Postfix/Dovecot service. The permanent /opt/spamgate/spamgate foreground launcher, spamgate-worker, /opt/spamgate/data and ports 38470/38472 remain unchanged.

## Tests

New Linux subprocess regressions cover bounded output, five-second hangs, normal and nonzero exit behavior, explicit malformed and contradictory IDs, legacy silent success/failure, valid numbered IDs, and missing executables. Isolated helper tests are runnable with Go 1.23; full repository and native release qualification must be confirmed by exact-commit CI and host evidence. This does not close GitHub issue #8.
