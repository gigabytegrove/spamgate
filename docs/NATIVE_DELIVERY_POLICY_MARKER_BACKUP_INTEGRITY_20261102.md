# Native delivery-policy marker backup integrity — 2026-11-02

## Failure addressed

The worker refuses invalid `.delivery-policy.initialized` evidence on cold start, but previous cold backup creation and ZIP verification checked only the presence of that filename. An archive with internally consistent SHA-256 hashes could therefore pass `Verify` and `Restore` while producing an unusable native worker state.

## Contract

- Cold backup validates the marker as a stable, real, mode-0600 file with the exact bytes `spamgate-delivery-policy-v1\\n`. Symlinks, wrong permissions, changed identity and wrong content are refused without rewriting evidence.
- Archive verification validates the exact marker payload, independent of ZIP mode headers. Restored files are private 0600 files. An invalid marker blocks both verification and restore before any destination directory is published.
- The existing state/marker pairing and `initialized` witness checks remain in effect. Legacy snapshots without a marker remain eligible under their existing migration rules.
- These checks establish consistency, not authenticity: an attacker who can rewrite all archive bytes and hashes can still forge a consistent snapshot.

## Qualification

Regression cases cover wrong marker version, truncation, appended bytes, unsafe permissions, symlinks, forged ZIPs with matching SHA-256 manifests, failed restore nonpublication, and valid restore. Full Go/race, native upgrade/rollback, and disposable Postfix/Dovecot CI remain required after commit. Production cold-restore and actual host qualification remain outstanding. No running mail server should be changed automatically.
