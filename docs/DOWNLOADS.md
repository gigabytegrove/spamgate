# SpamGate native builds and GitHub Releases

The GitHub repository is the source of truth. Release publication is performed **locally on dockeradm** with `gh`; no GitHub Actions workflow is required or enabled for release automation.

## v0.6.0-alpha.13 native Linux pair

A foreground-native deployment consists of **two separate AMD64 Linux binaries**:

- `spamgate-run-linux-amd64`, installed as `/opt/spamgate/spamgate-run`, is the stable launcher and update supervisor.
- `spamgate-linux-amd64`, installed as `/opt/spamgate/spamgate`, is the actual mail worker updated in place.
- `spamgate-windows-amd64.exe` is a separate Windows worker developer build; the independent runner is not yet validated on Windows.
- `SHA256SUMS.txt` protects the exact released artifact bytes; neither SHA-256 nor unsigned Windows binaries are a substitute for publisher signing.

On dockeradm, build and qualify the complete source from the exact approved commit with `bash scripts/build-github-assets.sh`. **Do not publish** if the command fails. It runs Go tests, race detection, static analysis, JavaScript rendering regressions, the existing supervisor restart/rollback integration, the new independent runner integration, and cross-compilation. The release includes all **four** files above. It is marked as a prerelease.

For the **one-time transition** of a stopped alpha.9 foreground server, use the reviewed `scripts/bootstrap-foreground.sh /opt/spamgate` from the exact tagged source. It verifies both GitHub assets and preserves the old worker separately; it does not touch Postfix, the Milter environment, `/opt/spamgate/data`, or the legacy `.spamgate-backup`. It also does not start a service.

Start the installed pair by replacing `./spamgate` with `./spamgate-run` while keeping the rest of the existing invocation unchanged:

```sh
cd /opt/spamgate
SPAMGATE_MILTER_LISTEN=127.0.0.1:38472 \
SPAMGATE_MILTER_TRUSTED_CIDRS=127.0.0.1/32 \
./spamgate-run -data /opt/spamgate/data -listen 0.0.0.0:38470
```

The launcher keeps the terminal attached so runtime logs, update failures and rollback events remain visible. It never downloads software by itself: the authenticated SpamGate update UI stages a published, verified worker, and a private worker exit code requests the runner to replace it. See [native runner design](RUNNER_ALPHA13.md).

The managed systemd/Docker integrated-supervisor deployment remains a separate mode and must not be mixed with the foreground launcher on the same data directory. Do not start multiple SpamGate instances against the same listening ports and journal.
