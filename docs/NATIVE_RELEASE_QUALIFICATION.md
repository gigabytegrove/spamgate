# Native release qualification and controlled publication

**Status:** Release engineering only. A successful GitHub build is not live mail-host qualification, nor is a release an instruction to modify the mail host automatically.

## Immutable deployment contract

- `/opt/spamgate/spamgate` is the existing permanent foreground launcher. It is **not** replaced during normal application updates.
- `/opt/spamgate/spamgate-worker` is the updateable worker; it owns the UI and Milter.
- `/opt/spamgate/data` remains persistent and is never replaced by a release.
- Management HTTP uses 38470 and the local Postfix Milter uses 38472. The release scripts never change Postfix, Dovecot, systemd or running processes.
- The Linux legacy `spamgate-linux-amd64` release asset is byte-identical to the **worker**, not the launcher. It must never be installed as `/opt/spamgate/spamgate`.

## Build and verify on the authoritative build host

On dockeradm, in the checked-out clean `gigabytegrove/spamgate` main source:

```bash
cd /root/spamgate-source
# Verify this path is the intended source checkout; do not assume it exists on all hosts.
git switch main
git pull --ff-only origin main
REVISION="$(git rev-parse HEAD)"
bash scripts/build-github-assets.sh /root/spamgate-native-assets
bash scripts/verify-native-release-assets.sh /root/spamgate-native-assets 0.6.0-beta.2
```

The build gate runs Go unit, race and vet, native launcher/update regressions, UI tests, host probes and negative asset fault-injection tests. It requires a patched Go toolchain, C compiler, Node, Python, sha256sum and a working outbound Go toolchain checksum service.

Publication is a **separate explicit operation**, never a side effect of a push or GitHub Actions build. With `REVISION` still bound to the exact verified main commit:

```bash
TAG=v0.6.0-beta.2
SPAMGATE_PUBLISH_CONFIRM="$TAG@$REVISION" \
  bash scripts/publish-native-release.sh /root/spamgate-native-assets 0.6.0-beta.2 "$REVISION"
```

The publisher checks the local clean tracked source, remote main SHA, absent existing tag, four executable identities, exact manifest and checksums. It creates an immutable prerelease with all five required assets. It never changes the mail server.

For independent GitHub CI qualification, manually dispatch `SpamGate native release qualification` on `main` with the exact `expected_sha`; the workflow only uploads artifacts and cannot publish releases (`contents: read`). Do not confuse CI artifacts with updater-compatible published GitHub releases.

## Operator-controlled installation

After publication, sign in to the running SpamGate UI as an administrator. Under **Software Updates**, select **Check for updates**, **Download and verify**, then **Install verified update**. The worker selects `spamgate-worker-linux-amd64`, checks `SHA256SUMS.txt`, stages the update in `/opt/spamgate/data/updates`, and asks the permanent launcher to replace only `/opt/spamgate/spamgate-worker`, restart and probe the new version. The launcher maintains the previous worker for rollback.

If the UI reports unsupervised installation or refuses staging, **do not** manually overwrite the launcher, launch a second instance, change Postfix `milter_default_action`, or run an ad-hoc ZIP installer. Diagnose the existing parent/child process and permissions first.

## Explicitly unverified production gates

No CI run establishes customer-mail delivery, DKIM/ARC interoperability, classifier false-positive bounds, tenant isolation, real Postfix HOLD/release, Dovecot mailbox placement, or production recovery. Issues #1–#9 remain open until their respective acceptance evidence is captured. Release assets are checksum-verified but not independently signed. The previously agreed mail-host update and rollback observation is still required before calling this a long-term beta.
