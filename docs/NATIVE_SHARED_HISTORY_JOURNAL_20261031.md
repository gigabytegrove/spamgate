# Native shared history journal coordination — 2026-10-31

Production gates #2 and #6: the Linux events journal now uses a permanent
private flock (.events-journal.lock) for startup reads, appends and compaction.
Independent Store instances reconcile newly appended evidence before writing
or compacting, preventing stale-memory compaction from dropping accepted-mail
history. Corrupt, missing, replaced or incomplete journals fail closed.

The Linux lease is advisory: unrelated external writers must not edit events.jsonl.
Non-Linux builds retain a process-local mutex for existing single-process use;
sharing one data root across independent Windows processes is not qualified.
Do not unlink the lock inode while SpamGate runs. The append + fsync model
still requires operator repair of a partially written trailing event. This
does not qualify power-loss recovery, disk-full recovery or real mail hosts.

Regression tests cover independent writers, concurrent appends, stale
compaction, corrupt records and symlink lock refusal. The native Linux
launcher, worker, data root, Postfix fail-open disposition and Milter ports
38470/38472 are unchanged. No production host was touched.
