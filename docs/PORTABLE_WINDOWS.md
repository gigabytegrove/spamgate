# SpamGate — Windows desktop first run

**Windows binary first; optional Windows Service later. No command-window launcher.**

SpamGate is a Go executable compiled for the Windows GUI subsystem. Double-click `spamgate.exe` — **do not run a `.cmd` or PowerShell launcher**. It starts the local daemon and opens the browser-hosted management console at `http://127.0.0.1:38470`. A browser-based Web UI is intentional; there is no embedded WebView, Electron app, or console shell.

1. Obtain a **trusted, security-reviewed** Windows archive from a verified release source. The current unsigned development build is not a production release and has not been validated on Windows Defender.
2. Extract the ZIP and double-click **`spamgate.exe`**. Administrator privileges and Windows Service registration are not required for a portable test.
3. On a new data directory, SpamGate displays a **native Windows first-run dialog** containing the one-time claim key. Use `Ctrl+C` in the dialog to copy its contents, then enter the claim key in the first-run browser form.
4. Complete the administrator setup. The process continues to run until you stop it from Task Manager or Windows service management. **Closing the browser tab does not stop the filter.**
5. Data and startup logs live in `%LOCALAPPDATA%\SpamGate`, including `%LOCALAPPDATA%\SpamGate\logs\spamgate.log`. The administrator claim key is written to the log; protect access to this directory. The Web UI binds to `127.0.0.1:38470` by default. Mail-facing ports are not automatically opened.

To run continuously at boot, use the Windows Service installer from a **signed and verified release** instead; services do not display browser windows or claim-key dialogs. This portable profile and the service profile intentionally use different data paths.

## Troubleshooting

If the browser does not open, manually visit `http://127.0.0.1:38470/`. If the local health check fails, inspect `%LOCALAPPDATA%\SpamGate\logs\spamgate.log` and check whether another application is using TCP 38470. No special script execution policy is needed.

Do not expose the administration HTTP listener over the public internet without TLS and access restrictions. If Defender flags the EXE or ZIP, inspect Protection History and report the detection; **do not disable Defender or create an antivirus exclusion**. The preview is unsigned and has not been verified on native Windows.
