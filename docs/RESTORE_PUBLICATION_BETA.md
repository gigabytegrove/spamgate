# Native beta backup/restore publication safety

Offline restore verifies the backup manifest before extracting. Each restored
file is independently checked against the manifest SHA-256 while being written
and fsynced, guarding against archive mutation between inspection and extraction.

On Linux amd64/arm64, final publication uses the kernel's
`renameat2(RENAME_NOREPLACE)` syscall. It atomically moves the staged,
verified directory only when the destination does **not** exist, even if
another process creates that destination after the initial check. It then
fsyncs the parent directory. An unsupported Linux architecture fails closed
rather than falling back to overwrite-capable rename. Windows uses its
existing-destination-refusing directory rename behavior.

The test suite covers normal publication, concurrent destination creation,
and refusal to replace existing data. This remains an **offline-only**
operation with SpamGate stopped. Real production-host backup, restore,
update and rollback are not yet qualified. No running mail server is changed.
