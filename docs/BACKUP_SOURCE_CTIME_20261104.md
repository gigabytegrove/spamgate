# Native Linux backup source ctime verification — 2026-11-04

Gate: #8 (backup and disaster recovery). This is engineering progress, not production qualification.

## Defect and correction

The offline ZIP creator checked source identity, length and modification time after copying, but an in-place rewrite of equal length followed by restoration of the old mtime could evade those checks. The Linux implementation now also compares inode change time (seconds and nanoseconds) captured before opening and after copying. Missing Linux inode metadata fails closed. Non-Linux builds retain their existing behavior.

Files: internal/backup/backup.go, source_change_time_linux.go, source_change_time_other.go, source_change_time_linux_test.go.

## Evidence and limits

An isolated Linux Go 1.23.2 test passed for same-inode, same-size, restored-mtime mutation and missing metadata. Initial test fixture accidentally used unequal-length replacement text and failed its precondition; corrected the fixture to equal-length text and reran successfully.

This is not an immutable snapshot: a privileged actor could tamper with inode timestamps, changes can occur outside the sampled interval, and application-level consistency still requires stopping the worker and holding the offline lock. Full repository tests, exact-commit CI and real-host restore/rollback qualification must be recorded separately.

No production Postfix or Dovecot configuration is modified. The native launcher, worker, data path and Milter ports are unchanged.
