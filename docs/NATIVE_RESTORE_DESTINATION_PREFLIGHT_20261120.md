# Native cold-restore destination preflight — 2026-11-20

## Scope
Issue #8: reject invalid cold-restore destinations before reading authentication material. The existing restore engine already checks the parent and destination after authenticated verification; the CLI now performs the same non-destructive contract checks earlier.

## Changes
- Require a new, nonexistent target with an existing directory parent.
- Reject symlinked parent components, non-directory ancestors, root target and existing files or directories.
- Keep immutable active-data and backup-source overlap checks ahead of the destination check.
- Keep the restore engine's independent validation and atomic no-replace publish as authoritative. Preflight is not a race-free security primitive.
- Add table-driven filesystem regressions and a CLI ordering regression with missing credentials.

## Architecture
No changes to /opt/spamgate/spamgate, spamgate-worker, /opt/spamgate/data, or Milter ports 38470/38472. No Docker replacement, service restart or mail-server configuration changes.

## Qualification boundaries
The GitHub workflow must be inspected for the final commit, not a preceding commit. Real mail-host acceptance, production restore, concurrent path mutation, full browser acceptance, classifier false-positive qualification and all other open production gates remain unverified by this change. The October 31 target has passed; this is not a beta-readiness declaration.
