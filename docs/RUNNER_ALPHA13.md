# SpamGate native process supervisor — v0.6.0-alpha.13

## Exactly two independent binaries

- `/opt/spamgate/spamgate-run`: stable native Linux **supervisor**. It owns worker lifetime, upgrade transactions, health verification, retries, and rollback. It is not modified by in-app updates.
- `/opt/spamgate/spamgate`: **actual SpamGate worker**. It serves the UI, scan API and Milter, holds the same config and durable mail history, and is atomically replaced **in place** on a verified update.

The foreground invocation is:

```bash
cd /opt/spamgate
SPAMGATE_MILTER_LISTEN=127.0.0.1:38472 \
SPAMGATE_MILTER_TRUSTED_CIDRS=127.0.0.1/32 \
./spamgate-run -data /opt/spamgate/data -listen 0.0.0.0:38470
```

The runner does not itself bind the management or Milter ports. It forwards the original CLI arguments and environment to the worker, waits until the worker is healthy, logs its PID, and continues running in the same terminal. `Ctrl+C` stops the worker gracefully. The update request asks **only the child** to exit with a private code, leaving `spamgate-run` running.

The updater verifies the staged GitHub worker binary checksum and version, saves an independent rollback at `data/updates/managed.previous`, atomically replaces `/opt/spamgate/spamgate`, starts the new worker, then verifies that the new **version** responds at `/healthz`. If the replacement exits or fails health checks, the runner restores the original executable **at the same path**, restarts it, and records `rolled_back` in `data/updates/last-update.json`. It never destroys the old `spamgate.spamgate-backup` left by alpha.9.

A successful response from `/api/v1/update/install` is a **request accepted**, not proof of update. The software update UI exposes the real installed-worker path and persistent outcome. Logs remain visible in the terminal. This is not service-manager automation or a Docker sidecar; it is an independent compiled launcher alongside the mail engine.

## One-time alpha.9 migration

The existing alpha.9 worker uses a detached update helper that can stop itself before verifying restart. **Do not use its in-app Install button to upgrade to this release.** Instead, with the service already stopped, run the reviewed `scripts/bootstrap-foreground.sh` from this tagged source on the mail host. It downloads two release assets (`spamgate-linux-amd64` and `spamgate-run-linux-amd64`) plus SHA256SUMS, verifies them, preserves the old worker separately, installs them alongside each other, and **does not start or stop the service**. Your `/opt/spamgate/data` and Milter settings remain unchanged.

The script refuses to run if the configured management listener is occupied. After the one-time migration, launch `./spamgate-run` exactly as above. The next in-app update can replace `./spamgate` without modifying the independent runner.

## Safety and scope

The runner is only qualified for native Linux in this release. Windows has separate executable-lock behavior; the Windows worker remains available but has not been migrated to this independent runner. The existing Docker/systemd integrated supervisor remains until separately transitioned and tested; do not overwrite a managed executable from another supervisor. A successful HTTP health check is not proof of end-to-end Postfix delivery or Milter verdict correctness.

The updater requires Linux AMD64, a regular installed worker, valid staged metadata, matching SHA-256, and a forward version. It refuses symlink executable paths. A bounded crash restart (maximum 3 attempts) prevents an infinite worker loop. The runner itself must be protected with appropriate filesystem ownership and permissions. If launched from a root shell, its worker runs with that same privilege; use a dedicated account after verifying mail and data permissions in a separate controlled deployment.

## Release assets and tests

The alpha.13 GitHub Release must include Linux AMD64 `spamgate-linux-amd64` and `spamgate-run-linux-amd64` plus the Windows worker `spamgate-windows-amd64.exe` and `SHA256SUMS.txt`. The independent runner is covered by real local subprocess integration tests for forward replacement, failed startup rollback, in-place installed-version equality, SHA-256 tampering, symlink refusal and version-ordering. Existing Go, JavaScript and integrated-supervisor tests must also pass before publication.
