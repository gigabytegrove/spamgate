# Maildir evidence pathname-race hardening — 2026-10-31

Scope: SpamGate production gates #1, #6 and #9. Read-only qualification tooling only; no changes to Milter behavior, Postfix, Dovecot, systemd, or the running mail host.

## Reproduced risk and fix

The Maildir evidence scanner opened a root directory descriptor but then opened its new/cur subdirectories by rebuilding absolute pathnames. An operator-supplied Maildir path could be renamed or replaced between those operations, redirecting evidence scanning to a different tree. The scanner also accepted a directory entry as a regular file before reopening it, without comparing its inode identity or detecting observed in-place mutation during header parsing.

The scanner now:
- Validates the opened root directory against the preceding lstat identity.
- Opens new/cur strictly relative to the already opened root descriptor using O_DIRECTORY and O_NOFOLLOW.
- Restricts child names to the exact Maildir new/cur names.
- Checks a message's listed inode against the opened inode, then checks inode, size, mtime_ns and ctime_ns again after reading headers.
- Refuses the report on substitution, unexpected directory/file types or observed mutation; the existing exclusive-create output contract prevents publishing incomplete evidence.

Nine new hermetic Python tests cover path replacement, symlinked roots/children, child-name traversal, file inode replacement, in-place writes, nonregular files and valid stable reads. The existing end-to-end synthetic Maildir evidence suite remains enforced.

## Evidence boundaries

Descriptor-relative reads prevent redirection through a renamed root path after it is opened, but cannot authenticate an operator-provided Maildir or freeze writers that do not coordinate. A malicious writer may still alter data outside the observation window; reliable host qualification requires stopped/coordinated writers or a trustworthy snapshot and independent Postfix/Dovecot evidence.

The native architecture remains /opt/spamgate/spamgate (foreground launcher), /opt/spamgate/spamgate-worker, /opt/spamgate/data, HTTP 38470 and Milter 38472. No Docker substitution, mail-host deployment, or automatic service restart.

## Remaining cumulative gates

Issues #1–#9 remain open pending actual production-host delivery/hold/restore evidence, durable failure injection, authentication interoperability, classifier false-positive evaluation, tenant policy enforcement, retained diagnostics, browser acceptance and native update/rollback.
