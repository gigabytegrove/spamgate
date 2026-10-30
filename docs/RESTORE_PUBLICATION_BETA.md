# Native beta backup/restore publication safety

Offline restore verifies the backup manifest before extracting. Each restored
file is now independently checked against the manifest SHA-256 while being
written and fsynced; a changed archive cannot silently publish different
bytes between initial verification and extraction.

On Unix, the final restore destination is reserved with an exclusive
directory creation before the staged directory is renamed over the empty
reservation. An already-existing destination, including one created after
the initial check, is refused. A destination that another writer populates
cannot be overwritten by the rename; failure cleanup never recursively
removes a destination. The parent directory is fsynced after publication.
On Windows, the platform rename's existing-destination refusal is retained.

This is **offline-only** and requires SpamGate to be stopped. The test suite
covers normal publication and a concurrent destination containing data.
It does not certify a live production-host restore, data migration, actual
systemd update or rollback. No running mail server is changed.
