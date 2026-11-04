# Classifier corpus pathname identity hardening — 2026-11-04

## Root cause
The evaluator checked the opened file descriptor after evaluation, but not the original pathname. An attacker or concurrent process could rename or unlink the original and install a different regular file with the same size and modification time. The original descriptor would still pass stability checks, while the pathname used as evidence now referred to different bytes.

## Correction
The evaluator now performs both descriptor and pathname verification before emitting JSON. The path must still exist, remain a regular file (not a symlink), and identify the same filesystem object opened at the start. A changed pathname returns exit code 2 and no qualification report. Regression tests cover same-size/same-mtime replacement, unlink, symlink replacement, and in-place metadata change.

## Boundaries
This remains a best-effort check: concurrent modifications after final verification, filesystem timestamp manipulation, and mutable inode contents cannot be ruled out. Use a trusted immutable corpus snapshot and --corpus-sha256 for evidence integrity. This does not establish classifier representativeness, live mail delivery, or beta qualification.

## Verification command
go test ./cmd/spamgate-eval -count=1

No running Postfix/Dovecot configuration is changed by this evaluator fix.
