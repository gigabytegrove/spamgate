> **Native beta release publication (2026-10-31):** The previous manual GitHub Actions release workflow could not publish the split native layout: it compared the executable version to the `main` branch name and omitted the permanent launcher and dedicated worker. The corrected workflow now qualifies and uploads artifacts only; `scripts/publish-native-release.sh` is the explicit local `gh` publication path after full `scripts/build-github-assets.sh` qualification. The exact four binaries and `SHA256SUMS.txt` are required, and normal updates are performed in **Software Updates** without overwriting `/opt/spamgate/spamgate`. See [native release qualification](NATIVE_RELEASE_QUALIFICATION.md). Source changes are not a published release.

# Download and install SpamGate (Linux AMD64)

## Native foreground installation — alpha.16+

| Release asset | Install on the mail server as | Role |
|---|---|---|
| `spamgate-launcher-linux-amd64` | `/opt/spamgate/spamgate` | Permanent supervisor; starts child, performs in-place worker updates and rollback |
| `spamgate-worker-linux-amd64` | `/opt/spamgate/spamgate-worker` | Application, HTTP admin UI, scanner and Postfix Milter |
| `SHA256SUMS.txt` | Verification only | Verify both exact released binaries |

The name of the downloaded file is not the name of the installed executable. Both binaries must be present, but you only manually **launch `./spamgate`**.

`spamgate-linux-amd64` is deliberately an identical-byte **legacy worker** asset for older (`./spamgate` worker or `./spamgate-run` supervisor) installations and managed systemd/Docker supervisors. **Never install this legacy asset as the new `./spamgate` launcher.** `spamgate-run-linux-amd64` was a temporary alpha.13–alpha.15 layout and is superseded for new native foreground installs.

## Upgrading an existing directly launched `./spamgate`

1. Publish the exact alpha.16 GitHub prerelease only after all build/test gates pass.
2. Stop the existing `./spamgate` in its terminal. Do not start or install over a running process.
3. Use `scripts/migrate-native-launcher.sh /opt/spamgate [local-asset-directory]` from the verified alpha.16 source; the optional asset directory contains both downloaded binaries plus `SHA256SUMS.txt`. Without a directory, the helper uses authenticated `gh release download`.
4. The helper checks the original process is stopped, verifies hashes and versions, preserves the old application under a `spamgate.pre-native-split-<old-version>` filename, and installs the corrected pair without replacing `/opt/spamgate/data`.
5. Start with your existing environment and args:

```bash
cd /opt/spamgate
SPAMGATE_MILTER_LISTEN=127.0.0.1:38472 \
SPAMGATE_MILTER_TRUSTED_CIDRS=127.0.0.1/32 \
./spamgate -data /opt/spamgate/data -listen 0.0.0.0:38470
```

Confirm the `spamgate` parent starts `spamgate-worker`, HTTP `/healthz` succeeds, and the admin Software Updates view reports a supervised installation. All subsequent native updates target `spamgate-worker`, not the launcher. Old staged update metadata must be replaced by staging a new worker update after migration.

See [step-by-step migration and recovery](NATIVE_LAUNCHER_ALPHA16.md) and [update internals](IN_APP_UPDATER.md).

## Other deployment modes

Systemd/Docker and Windows retain their existing supervised-worker mechanisms and compatibility assets until specifically migrated and qualified. Do not run both the native foreground launcher and another service manager over the same ports or data directory. Checksums verify integrity relative to the published manifest but do not constitute independent publisher signing.

**Release gate:** The presence of alpha.16 *source* does not indicate a published or qualified alpha.16 binary. Do not overwrite the existing working installation until a verified prerelease with both new assets is available.
