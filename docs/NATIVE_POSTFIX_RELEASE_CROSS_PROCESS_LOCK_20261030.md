# Native Postfix hold release: cross-process serialization (2026-10-30)

Issue #9 — privileged queue action safety; issue #1 — disposition evidence.

## Defect and correction

The existing `postfixHoldOperationMutex` serialized HTTP requests only inside
one Go process. A second native SpamGate worker sharing the same persistent
data directory could independently read the same Postfix hold inventory,
persist a release intent and execute `postsuper -H`. The per-process mutex
did not establish cross-process exclusivity.

Linux release now takes an advisory `flock(LOCK_EX|LOCK_NB)` on the persistent
`/opt/spamgate/data/.postfix-hold-release.lock` **before** reading the scan
or inventory. It retains the lock through ownership correlation, durable
pre-command audit, command execution and final audit. The request waits at
most five seconds, then fails with HTTP 503 without touching Postfix.
The lock file is never automatically deleted. The directory must be a real
non-group/world-writable directory; the lock must be a private regular file
owned by the running UID with one hard link. Symlinks and unsafe modes fail
closed. The process-local mutex remains in place.

Non-Linux builds deliberately refuse the native Postfix release operation
rather than claiming equivalent locking. No Docker deployment, Postfix
configuration or running mail host is modified by this change.

## Qualification

Unit regressions exercise independent file descriptors, timeout, lock reuse,
symlink/hardlink/mode refusal and the actual authenticated HTTP handler under
lock contention. The handler test verifies that neither inventory nor
`postsuper` injection is called and that the durable release audit remains
unchanged until the lock is available.

**Limitations:** `flock` is advisory; manual `postsuper`, another program
that does not honor the lock, or a malicious process with the same filesystem
ownership can still race. A queue ID plus envelope/time correlation is not
cryptographic ownership evidence. This change does not provide a privileged
helper, prove Postfix command success, prove Dovecot mailbox placement, or
qualify a real host. Native Postfix/Dovecot end-to-end evidence and a
minimum-privilege host helper remain open production gates.
