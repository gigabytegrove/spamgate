# Downloading and testing SpamGate

**Current distribution is pre-release, not production-certified.**

Permanent native artifacts are intended to be published at the [private GitHub releases page](https://github.com/gigabytegrove/spamgate/releases). You must sign in to an account that has access to this private repository. Release assets are only downloadable after the GitHub Actions `Native development releases` workflow has succeeded; an unverified workflow commit does not establish that those assets exist.

Use the standalone `SpamGate-0.4.0-alpha.2-linux-amd64` executable for an unpackaged Linux x64 smoke test, or `SpamGate-0.4.0-alpha.2-windows-amd64.exe` for a Windows x64 development smoke test. Alternatively, the `*_UNSIGNED-DEVELOPMENT.tar.gz` archive contains the systemd installer and Postfix configuration helper; other platform bundles are packaged in the same workflow.

On Linux, after authenticating to GitHub and downloading the standalone binary, rename it to `spamgate`, check its SHA-256 against `SHA256SUMS.txt`, and run:

```sh
chmod 0755 spamgate
./spamgate -version
./spamgate -data "$HOME/.local/share/spamgate" -listen 127.0.0.1:38470
```

Visit http://127.0.0.1:38470 on that host and complete first-run setup. This does **not** attach to or alter your installed MTA. For persistent installation use the tested service installer from the platform-specific archive **only after validating the build for your environment**. Review [native MTA setup](NATIVE_MAIL_SERVERS.md) first.

Windows native development smoke test: download the EXE, inspect any Defender warning rather than bypassing it, and double-click the GUI executable. Its Web UI opens locally. This is an unsigned development binary and may be blocked by organizational policy. No publisher certificate or Defender clearance is claimed.

If GitHub Releases has no assets, inspect the workflow run in the private repository's Actions tab. Do **not** fall back to an outdated, unsigned chat attachment for production traffic. Chat-generated sandbox links are temporary and can fail independently of a valid archive.
