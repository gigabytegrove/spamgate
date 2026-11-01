# SpamGate source versions and build IDs

**Contract:** The source/product version and build version are independent.

- `internal/core/types.go` retains the source version (currently `0.6.0-beta.2`).
- Every qualified native build embeds a build ID using the **America/New_York**
  local date and 24-hour clock: `YYYYMMDD-HH`, with `HH` from `00` to
  `23`. For example, an automatic build at 01:00 Eastern on 2026-11-01 is
  `20261101-01`.
- Manual builds use that same date/hour and a letter suffix: `20261101-01a`,
  `20261101-01b`, through `20261101-01z`. A persistent, exclusive local
  reservation ledger in the output directory allocates the next available
  letter; concurrent builders cannot reuse an allocated number.
- A failed build **consumes its reservation**; do not recycle a failed ID to
  label different bytes. Local clean builds using a different output directory
  have independent ledgers. A release tag is immutable and cannot be
  re-published; compare exact Git commit and SHA256SUMS before publication.
- During the fall DST transition two different physical hours can have the
  same Eastern hour `01`. The second automatic reservation is **rejected**,
  not given the same build ID. A human can choose an explicitly marked manual
  suffix if a distinct second build is required. This is necessary under the
  requested `YYYYMMDD-HH` naming contract.

## Build and inspect

From a trusted source checkout on the **build host**, not the production MTA:

```bash
# A scheduled engineering/CI build (no letter).
SPAMGATE_BUILD_KIND=automatic bash scripts/build-github-assets.sh /var/tmp/spamgate-builds

# Manual builds auto-reserve a, b, ..., z within that output directory.
SPAMGATE_BUILD_KIND=manual bash scripts/build-github-assets.sh /var/tmp/spamgate-builds
# Optional explicit letter, if not already reserved:
SPAMGATE_BUILD_KIND=manual SPAMGATE_BUILD_LETTER=c bash scripts/build-github-assets.sh /var/tmp/spamgate-builds

/var/tmp/spamgate-builds/spamgate-worker-linux-amd64 -version
/var/tmp/spamgate-builds/spamgate-worker-linux-amd64 -build-version
/var/tmp/spamgate-builds/spamgate-worker-linux-amd64 -build-info
```

The build script runs the Go unit/race tests, host regression suites, UI tests,
and native migration regressions before reserving an ID. Then it compiles the
Linux worker, permanent launcher and Windows program from an exact Git commit
with matching embedded `BuildVersion` and `SourceCommit`.

`BUILD-INFO.json` includes the source version, build ID, Git SHA, build kind,
America/New_York timezone and qualification UTC timestamp. It is included in
`SHA256SUMS.txt`. The validator checks all five checksummed files, the actual
worker and launcher build probes, their source SHA, and release metadata; it
rejects mismatches, corruption and substituted executables. The four binaries
plus manifest and checksum file are six immutable release assets.

The local build output directory keeps its `.spamgate-build-ids` reservations
for later manual invocations. Do not delete that file and reuse a release
directory; use a new directory only for an independently tracked build lineage.
The Git SHA plus the checksummed artifact is the exact identifier for a
particular source tree within an hourly build slot. A build number by itself
does not certify binary equality.

## GitHub Releases and Software Updates

The release tag is `v<SOURCE>+<BUILD>`, such as
`v0.6.0-beta.2+20261101-01` or `v0.6.0-beta.2+20261101-01a`.
SemVer precedence determines the **source** upgrade first; for the same source
version SpamGate compares the numbered build IDs (automatic before manual a..z
within an hour). A legacy release with no build metadata is older than a
numbered build of the same source version.

The native publisher requires `SPAMGATE_PUBLISH_CONFIRM=<TAG>@<SHA>`, the
corresponding exact source commit, the verified six assets and an unused tag.
Publishing does **not** deploy or restart a mail server.

A newly compiled build-aware launcher knows how to install a newer numbered
build of unchanged source version, verifies the replaced worker's
`-version` and `-build-version`, and rolls back on failures. **Important
compatibility boundary:** the permanently installed launcher that predated
numbered builds cannot recognize `+BUILD` staging manifests, so it cannot
perform same-source build updates. Do not silently overwrite or replace the
running launcher. That launcher needs a separately qualified, explicitly
approved one-time migration before build-only in-app updates can be used there.
Build identity can still be previewed using the existing worker-only,
service-aware deployment helper; this is not a substitute for the normal
verified in-app update path once the launcher has been migrated.

Build numbering does not change the source version or promote a beta to
production, and no scheduled build auto-installs on the running mail host.
