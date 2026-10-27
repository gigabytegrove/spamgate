# SpamGate v0.4.0-alpha.2 standalone test downloads

These are **native x64 development test packages**, not installers. No Docker or service setup is required to launch them. Both contain only one executable, `README-FIRST.txt`, and a SHA-256 checksum file.

| Platform | File |
|---|---|
| Windows x64 | [SpamGate-v0.4.0-alpha.2-Windows-x64-STANDALONE-TEST.zip](SpamGate-v0.4.0-alpha.2-Windows-x64-STANDALONE-TEST.zip) |
| Linux x64 | [SpamGate-v0.4.0-alpha.2-Linux-x64-STANDALONE-TEST.zip](SpamGate-v0.4.0-alpha.2-Linux-x64-STANDALONE-TEST.zip) |

The repository is private. Sign in with a GitHub account that has access to the repository. On the file page use **Download raw file** if clicking the name opens the file viewer.

**Windows:** Extract ZIP, double-click `SpamGate.exe`. The browser UI listens on http://127.0.0.1:38470. On first run the setup key is presented in a native dialog. Data and logs use `%LOCALAPPDATA%\SpamGate`. No installer, PowerShell, CMD script, or administrator privileges are required for the portable test.

**Linux:** Extract ZIP and run `chmod +x ./spamgate` and then `./spamgate -data "$HOME/.local/share/spamgate" -listen 127.0.0.1:38470`. Open the URL on the same host, or use an SSH tunnel to access a remote server's loopback port. Ctrl+C stops the process. No mail system is modified.

**Security and validation:** These binaries were compiled from SpamGate `0.4.0-alpha.2` source using Go **1.23.2**, an outdated toolchain, because a newer compiler could not be downloaded in the working container. They are **for isolated local evaluation only** and must not be deployed for production mail routing. The Windows executable is **unsigned**, is **not Windows-tested**, and is **not certified as Defender-clean**. Do not disable Defender or override security blocks. Go tests, `go vet`, race tests, cross-compilation, ZIP integrity, and the Linux live startup/Web UI test passed. Permanent signed binaries from a current patched compiler remain to be produced.

Final ZIP SHA-256 checksums are in [SHA256SUMS.txt](SHA256SUMS.txt). Raw ZIP files were uploaded as Git blobs and validated byte-for-byte against these local checksums through matching Git object hashes.
