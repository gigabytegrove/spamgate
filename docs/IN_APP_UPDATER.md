# SpamGate v0.6.0-alpha.12 — stable installed-worker updates

## The defect corrected

In alpha.11, in-app updates replaced `/var/lib/spamgate/updates/running` while the original executable at `/usr/local/bin/spamgate` stayed unchanged. The active worker could be new, but operators inspecting the installed command would still see the old base version. On installation types without an integrated supervisor, an older update path could also terminate the process without a reliable restart.

Alpha.12 establishes a **single persistent installed worker path** on Linux: `<data-dir>/bin/spamgate`, normally `/var/lib/spamgate/bin/spamgate`. That file is the actual worker executable and is atomically replaced in place after the staged GitHub asset has passed SHA-256 verification. Its previous contents are retained for rollback. The supervisor keeps the service/container alive and verifies the new worker's `/healthz` before reporting a successful update.

The protected supervisor remains a separate executable in the root-owned image/installation. Do not turn `/usr/local/bin/spamgate` into a symlink to a worker executable owned by the unprivileged SpamGate service account: that could let a compromised service account influence programs subsequently executed as root. Therefore **in-place means the real installed worker binary**, not writing the root-owned protected supervisor.

## Native Linux

- Root-owned, protected supervisor: `/usr/local/bin/spamgate`.
- Actual running worker and stable in-place update target: `/var/lib/spamgate/bin/spamgate`.
- Preserved mail data: `/var/lib/spamgate` (config, persistent sessions, quarantine, history and spool).
- On the first upgrade to this layout, rerun the trusted `scripts/install-linux.sh` on the **actual mail application host**, with the matching alpha.12 binary in `scripts/spamgate`. It installs the protected base and updates the existing systemd service's entrypoint without changing Postfix settings.
- Startup selects the newest runnable version from the protected base, the previous alpha.11 `updates/running` overlay and the stable installed path. An older base never intentionally downgrades a newer installed worker. Invalid saved executables are rejected and the protected base remains available for recovery.
- For the running worker version use `/var/lib/spamgate/bin/spamgate -version`. The base supervisor's separate version can legitimately be older after an in-app update, so do not use `/usr/local/bin/spamgate -version` as the measurement of the running filter.

## Docker

The image-layer `/usr/local/bin/spamgate` is immutable, particularly with `read_only: true`. The **same stable worker path** (`/var/lib/spamgate/bin/spamgate`) exists inside the persistent named volume and survives container restarts/recreations. The protected base remains in the image, and `SPAMGATE_INPLACE_UPDATES=1` is set by the new Dockerfile. Recreate from the alpha.12 image **once** to activate this behavior; later in-app binary updates replace the persistent worker. They cannot update Alpine packages, image metadata or the Docker image tag; these still require image replacement.

## Windows and other launchers

The earlier supervised `updates/running.exe` overlay remains the Windows update strategy because Windows locks executable files that are running. Windows Service runtime qualification is outstanding. Unsupervised installations are not allowed to kill their process from the in-app updater. The Update UI displays the actual executable target and supervised status rather than claiming an immutable base was rewritten.

## Verification and limitations

Use `bash scripts/test-supervised-updates.sh` to test both legacy and stable-worker successful upgrades **and** intentionally failed replacements, with persistent sessions, a live supervisor and `/healthz`. The unit tests separately cover migration from a newer legacy overlay, exact installed-file promotion and rollback, and refusal of symlink executable paths. These tests do not qualify live Postfix mail delivery, long-running systemd operation, Docker image upgrades, Windows Service behavior, binary signing or OS-package upgrades.

Updates require the published GitHub executable and matching `SHA256SUMS.txt`; no update should be marked complete merely because the worker process exited. A self-published checksum provides integrity relative to the manifest, not independent signed release provenance. Deployment and rollback must preserve the existing SpamGate data directory and use the same browser origin to retain active sessions.
