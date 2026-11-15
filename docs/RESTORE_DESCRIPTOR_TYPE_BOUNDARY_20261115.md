# Linux restore descriptor type boundary

`VerifyRestored` performs an offline comparison; it never applies a restore to the running mail server. On Linux, `openRestoredRegularNoFollow` now rejects nonregular opened descriptors before handing them to the verifier, in addition to no-follow traversal of every pathname component. FIFO reads cannot hang waiting for a writer because the leaf is opened nonblocking. The opened inode is checked with `fstat` and the descriptor is closed on every failed check.

## Regression coverage

`go test ./internal/backup -run 'TestOpenRestoredRegularNoFollow' -count=1` covers a FIFO, a directory, a regular file, and the existing symlink cases. This is not a real Postfix/Dovecot or production restore qualification.

## Residual boundaries

A device node can have side effects at `openat` time before `fstat` rejects it. A privileged writer can race path renames or modify content concurrently. Run verification only on a stopped, isolated, access-controlled restored tree, and do not treat this check as atomic containment against privileged concurrent mutation. Real-host cold restore, rollback, data-permission and mail-delivery tests remain required before beta acceptance.
