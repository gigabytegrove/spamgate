# SpamGate alpha.17 — History integrity engineering (unreleased)

## Scope

Native Linux remains `./spamgate` launcher supervising `./spamgate-worker`; the application still writes its scan history to `<data-dir>/events.jsonl`. This pass does **not** change the installation layout or run an update on any live host. The currently published alpha.16 remains the production observation baseline.

### Data-directory single-writer protection

- At worker startup, before opening `Store` or starting mail listeners, acquire a nonblocking Linux `flock` on `<data-dir>/.worker.lock`.
- Keep the open lock descriptor for the entire worker lifetime, including asynchronous HTTP, SMTP, Milter scans and history compaction.
- If a second worker attempts to run on the same data directory, refuse startup with an explicit error **before** loading or modifying `events.jsonl`.
- Reject symlink and nonregular lock files. Leave the lock inode on disk after shutdown; kernel releases advisory ownership when the process exits.
- The launcher does not hold the lock; it replaces workers sequentially. The native Windows build still compiles but Windows-specific cross-process locking has **not** been implemented/qualified by this Linux-focused change.

The lock protects against accidentally starting **two cooperating SpamGate workers** at once. It does not protect against external editors that ignore advisory locking, disk loss, filesystem corruption, malicious root operators, or two machines writing the same shared filesystem without reliable locks.

### Administrator-only read-only journal reconciliation

`GET /api/v1/history/integrity` scans `events.jsonl` from disk (bounded memory and a 15-second API deadline), reports file presence, size, SHA-256, total journal records, unique scan IDs, loaded retained scans, and missing/mismatching retained entries. It never serializes addresses, subjects, bodies, message IDs, or raw journal lines. It does not compact, overwrite, repair, truncate, or restore anything.

Possible statuses: `ok`, `missing`, `mismatch`, `corrupt`, `unreadable`. A `missing` file on a brand-new never-scanned installation does not prove historical deletion; consult data-path context. A mismatch means investigate without writing.

**Important:** `events.jsonl` is append-only between compactions; duplicate IDs represent revisions, so unique scan IDs can be lower than journal record lines. Retention and `max_history` can make the active retained count lower than the journal count. The endpoint is a consistency check **against in-process loaded state**, not a cryptographic proof of history completeness across past incidents or independent durable backup.

### UI behavior

- In All Messages, admins can click **Verify on-disk history** to compare memory against the saved journal.
- Failed essential message/history API calls produce an explicit error instead of being represented as an empty successful history response.
- Bayes, fuzzy, neural, and signals are optional; a failure from any one no longer suppresses a successful message-list and statistics refresh.
- The interface separately identifies a missing integrity result and a known disk/memory mismatch, and escapes untrusted error text.

### Qualification

- Linux lock conflict/reacquisition and symlink/nonregular-file tests.
- Disk consistency, duplicate-ID revisions, missing/truncated/corrupt journal, privacy, cancellation tests.
- Authorized admin-only HTTP audit test.
- Browser rendering and optional-subsystem-failure isolation tests.
- Full native Go tests and race tests, vet, Node UI regressions, and Linux/Windows build checks through a **nonpublishing** Actions workflow.

## Not certified by this pass

Postfix/Dovecot mailbox delivery, accurate MTA rejection/hold evidence, backup/restore drills, retention-compaction disaster recovery, external tampering, Windows worker ownership, all-history classifier migration, and production rollout. Keep the existing `/opt/spamgate/data/events.jsonl` backed up and do not change the live installation until exact source qualification passes.
