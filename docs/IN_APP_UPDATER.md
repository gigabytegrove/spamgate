# SpamGate 0.6.0-alpha.11 — supervised updates

The in-app install workflow is supported only when SpamGate is running through its **integrated supervisor**. This is the same Go executable invoked as the permanent service/container entrypoint with `-internal-supervise`; it is **not** an extra Docker container, a privileged web API, or a separately installed agent.

## What changed

- In a supervised worker, the Install button first verifies the staged release, responds to the browser, and gracefully stops the worker with a private exit code 75. The supervisor remains alive.
- The supervisor verifies the exact staged SHA-256 metadata, preserves the previous executable, copies the update atomically into the persistent data volume, and checks the replacement executable's `-version` before starting it.
- The replacement must respond successfully to a local `/healthz` request within 18 seconds. A failed version check, start, or health probe rolls back the active binary and restarts the previous version.
- The last update result (`checking`, `healthy`, `rolled_back`, or `failed`) is written to `updates/last-update.json` and exposed by the authenticated update-check endpoint. `healthy` means local HTTP startup, not verified filtering or final mail delivery.
- Existing config, sessions, history, quarantine, and accepted SMTP spool stay under the original `-data` directory.
- Subsequent updates operate independently of the base executable in `/usr/local/bin`. A newer base binary/image supersedes an older overlay at startup, rather than silently downgrading it.
- No update endpoint invokes a shell, edits Postfix, or controls the Docker socket.

## Initial transition: required once

Existing `0.6.0-alpha.10` installations do **not** yet have an integrated supervisor. Installing `0.6.0-alpha.11` using the previous in-app helper may stop the application without restarting it. **Do not use the old install-and-restart button for this transition.** Deploy the new binary through the normal native installer/service update or rebuild and recreate the Docker container once. This changes the systemd `ExecStart`, Windows Service `ImagePath`, or Docker `ENTRYPOINT` to include `-internal-supervise`. Subsequent verified in-app releases can update the supervised worker while keeping the service/container supervisor alive.

If running a custom service launcher or standalone interactive executable without `-internal-supervise`, the new Install endpoint will return HTTP 409 and keep the current process running; it will not kill an unmanaged service. Run a supervised launcher before using in-app install.

## Trust and operational limits

GitHub Releases is the source; `pending.json` and staged bytes are hash-verified twice. Release binaries must be built from an identified commit and distributed under the existing GitHub asset names and checksum manifest. A self-published checksum is an integrity measure, not a substitute for signed release provenance.

Because the supervisor keeps an active worker in its own writable data volume, restrict that directory to the SpamGate service account and do not run the supervisor as root. This scheme intentionally never overwrites the root-owned `/usr/local/bin/spamgate` during an in-app update. Docker image rebuilds remain the authoritative way to update base-image OS libraries; in-app binary updates do not patch the underlying image.

The supervisor's startup check verifies a local HTTP response only. It cannot prove that Postfix accepted Milter actions, mail was delivered, Windows SCM semantics are correct, or a specific mail-server upgrade is safe. Test these with real integrations and maintain a separate snapshot/rollback plan for production mail.
