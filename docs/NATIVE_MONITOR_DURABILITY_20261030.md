# Native operations history durability — 2026-10-30

Issue #6: durable diagnostic samples and alert acknowledgements.

## Defect

The operations history writer previously ignored errors opening, syncing, or closing the parent directory after atomic rename. It could therefore report a sample or acknowledgement as durable when the directory entry had not been confirmed on stable storage. If a post-rename sync failed, in-memory state also stayed at the old snapshot; another write could overwrite the already published record.

The read path also did not check file identity, length and modification time after reading, and the operations directory allowed group/world write access.

## Behavior

- Sync the data-directory parent after creating the operations directory, before publishing evidence.
- Write a private 0600 temporary file, require a complete write and fsync, close, then rename atomically.
- On Linux, fsync and close the operations directory; propagate errors.
- On a post-rename sync error, fail the operation and freeze the in-process monitor, including alert acknowledgement and history APIs, until an operator investigates and restarts. Do not overwrite potentially published evidence with stale memory.
- On restart, reload and validate the authoritative file before permitting new writes.
- Refuse group/world-writable operations directories and files that change identity/size/mtime while being read.

Windows directory fsync is not equivalent; the helper deliberately preserves the prior Windows behavior. A real power-loss/fault-injection exercise remains required.

## Regression coverage

`TestMonitorPostRenameSyncFailureFreezesUntilRecovery` exercises published-but-unconfirmed state, refusal of subsequent writes, restart recovery, and successful append.

`TestMonitorAcknowledgementSyncFailureCannotReportSuccess` ensures the API cannot falsely claim durable acknowledgement.

`TestMonitorRefusesWritableOperationsDirectory` rejects unsafe permissions.

## Unverified acceptance gates

Real filesystem power interruption, disk-full, read/write races on the production filesystem, multi-process writer coordination, alert injection on the mail host, and long-term browser evidence remain unqualified. No running mail host is modified by this change. All issues #1–#9 remain cumulative beta requirements.
