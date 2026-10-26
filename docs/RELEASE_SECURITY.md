# SpamGate Windows release integrity

## Current release hold

The previously distributed `v0.3.0-alpha.2` Windows ZIPs are **unsigned, unverified by Windows Defender, and compiled with Go 1.23.2**. They must not be advertised as security-cleared or production-ready. They are superseded for release purposes; no signed replacement has yet been published. The Microsoft Defender “Sample submission” prompt alone is not a finding that a named threat was detected.

## Release prerequisites (no shortcuts)

1. Build from an identified, reviewed Git commit with a current supported security-patched Go toolchain (at least Go 1.27.3 as of 2026-10-26). Log the exact toolchain version and source commit ID.
2. Run `go test ./...`, `go test -race ./...`, `go vet ./...`, and the documented runtime test. Windows binaries must be smoke-tested on an actual Windows x64/ARM64 system, including first-run and service installation.
3. Sign each Windows PE binary with a certificate from a trusted public code-signing authority using an approved Windows signing tool. Apply a trusted timestamp. Do not embed a certificate, key, password, PAT, or signing secret in the repository or the package.
4. Verify Authenticode signature and signing chain **after signing** on Windows (`Get-AuthenticodeSignature .\spamgate.exe`). Reject unsigned, invalid, or unexpected publisher identities.
5. Package transparent source-matched files only. Never use Base64-embedded payload launchers, runtime dependency downloaders, packed or obfuscated binary bootstrap, implicit AV exceptions, hidden installers, or security-policy bypasses.
6. Scan the exact signed ZIP and executable with an up-to-date Defender engine on Windows. Inspect Protection History and threat detections. Do not interpret a sample-request dialog as proof of malware *or* a clean verdict. If Defender reports a false positive, submit the exact unchanged artifact through Microsoft's official submission portal and wait for analysis.
7. Generate SHA-256 checksums of **final** signed release assets and publish them on a permanent GitHub Release. Do not modify archives after checksums are published.

## Developer archives

`scripts/build-release.sh` performs an explicit Go version check and produces `UNSIGNED-DEVELOPMENT` packages. These are for developer validation only. They are not Windows production release assets and must not be renamed or described as signed.

Linux distributions should also be built using a current supported toolchain, smoke-tested on each architecture, and distributed with checksums. This policy does not require Windows signing for Linux binaries.

## Installation principle

Use direct executable launch or a transparent, reviewed service installer. Do not recommend disabling Defender, adding antivirus exclusions, disabling SmartScreen, or using `-ExecutionPolicy Bypass`.

## Deferred

A fully automated release signing service requires an authorized organizational signing identity/certificate. It cannot be simulated by generating an arbitrary self-signed certificate.
