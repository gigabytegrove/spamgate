# SpamGate — Windows portable first run

This developer-preview launcher makes the native Web UI available without installing a Windows service, running PowerShell, modifying the registry, or requiring administrator rights.

1. Verify the ZIP archive SHA-256 hash. Extract the archive to an ordinary folder such as Downloads\SpamGate-Portable.
2. Double-click Start-SpamGate.cmd (or spamgate.exe). The executable opens the default browser only after the loopback health check succeeds.
3. Complete first-run administrator setup using the one-time claim key printed in the console window. Keep this key private.
4. Leave the console open while using SpamGate. Ctrl+C stops it. The launcher retains the window when a startup error occurs.
5. Persistent data: %LOCALAPPDATA%\SpamGate. Web UI: http://127.0.0.1:38470/. SMTP, Milter and Rspamd HTTP listeners are disabled by default.

If TCP port 38470 is occupied, stop the other process or manually run spamgate.exe -listen 127.0.0.1:38479 from a terminal. Never expose plain HTTP administration to the internet.

## Security and verification limits

This unsigned development executable has not been approved for production mail processing or tested with Microsoft Defender on Windows. Defender may request a sample or prevent the executable from running. Do not disable Defender, add exclusions or override its block. Check Windows Security > Protection history for a named detection; report the finding and exact archive hash.

The prior binary compiler Go 1.23.2 is outdated; source should be rebuilt using current security-patched Go 1.27.3 before broad distribution. A signed, validated Windows binary is still outstanding. See RELEASE_SECURITY.md.

A service deployment is separate from this portable profile and uses its own data directory. See INSTALLATION.md.
