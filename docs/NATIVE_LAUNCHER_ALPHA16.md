# SpamGate alpha.16 — native launcher migration

## Locked executable roles

- `/opt/spamgate/spamgate`: permanent foreground launcher; owns the worker lifecycle and update rollback
- `/opt/spamgate/spamgate-worker`: actual SpamGate application, web UI, scanner, and Postfix Milter
- `/opt/spamgate/data`: the **existing** persistent data directory; never recreated or deleted

The new Linux release ships `spamgate-launcher-linux-amd64` (launcher) and `spamgate-worker-linux-amd64` (worker). Both must report alpha.16 at the initial migration. The older `spamgate-linux-amd64` download **remains a worker for compatibility**, specifically so alpha.15 and the integrated systemd/Docker supervisors cannot mistake a launcher for the worker.

The old `spamgate-run` is not required by the new layout; leave any old file untouched for recovery, but do not start it alongside `./spamgate`. Windows/systemd/Docker remain on their previous supervision contract; this migration applies to the **manually started Linux foreground installation**.

## One-time migration while the original app is stopped

1. Confirm the current standalone `./spamgate` exits cleanly; use Ctrl+C in its original terminal. No mail or app instance may be listening on 38470/38472.
2. Download and verify the `v0.6.0-alpha.16` release with `gh` authentication; keep all three files together (`SHA256SUMS.txt`, `spamgate-launcher-linux-amd64`, `spamgate-worker-linux-amd64`). You can also let the migration helper download them with `gh`.
3. Run `bash scripts/migrate-native-launcher.sh /opt/spamgate /path/to/downloaded/asset-directory` (second path optional if authenticated `gh` exists). The helper refuses running processes and occupied ports, verifies both SHA-256 checksums and executable versions, preserves the previous standalone executable as `spamgate.pre-native-split-<version>`, then installs the two new executables without touching any saved data.
4. Start it in the same foreground shell with the established environment:

```bash
cd /opt/spamgate
SPAMGATE_MILTER_LISTEN=127.0.0.1:38472 \
SPAMGATE_MILTER_TRUSTED_CIDRS=127.0.0.1/32 \
./spamgate -data /opt/spamgate/data -listen 0.0.0.0:38470
```

Run `ps -eo pid,ppid,user,args | grep '[s]pamgate'`; `spamgate` must be the parent of `spamgate-worker`. The new update UI must report `install_mode=supervised`, the actual installed path `/opt/spamgate/spamgate-worker`, and an Install button only when a **verified** update is staged. Any alpha.15 staged data is stale after the naming transition; re-stage the next release in the UI instead of using the old manifest.

## Subsequent in-app updates

The child identifies its parent via `SPAMGATE_SUPERVISED=1` and `SPAMGATE_SPLIT_WORKER=1`; this selects the new `spamgate-worker-linux-amd64` asset. The launcher validates the staged payload, copies a rollback worker, atomically replaces `/opt/spamgate/spamgate-worker`, starts it, and verifies the new `/healthz` version. It never replaces `/opt/spamgate/spamgate` on an in-app update.

A launcher's `-version` stays at its original installed version even if later workers have newer versions. Preserve the old standalone backup and all historical updater files until after real Milter, session, and update verification.

**Status:** This document specifies a migration available only **after** the exact alpha.16 source passes all release checks and the corresponding assets are published. No existing mail host is automatically changed.

## Regression coverage

`scripts/test-migrate-native-launcher.sh` tests valid migration, checksum tampering refusal, old executable preservation and repeat-migration refusal. `cmd/spamgate-run/main_test.go` checks worker supervision, staged SHA-256, update and rollback. `internal/updater/updater_test.go` checks the legacy/new worker asset selection.
