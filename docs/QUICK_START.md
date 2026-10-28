# SpamGate — friendly first run (v0.4.0-alpha.6)

SpamGate is **standalone first**. Keep your existing mail server running normally while you learn the interface.

## First login

1. Start the SpamGate executable (for example, from `/opt/spamgate` with `./spamgate -data /opt/spamgate/data -listen 0.0.0.0:38470`).
2. Open `http://MAIL_SERVER_LAN_IP:38470` from a trusted LAN browser (or `http://127.0.0.1:38470` locally). Restrict port 38470 to trusted administrators or use an HTTPS proxy. The terminal shows a one-time first-run setup key when no administrator exists.
3. Create the administrator account. You will then enter **Setup guide**, not an engineering dashboard.
4. Select your mail server (Postfix, ISPConfig, cPanel/WHM, Exim, custom, or standalone testing), deployment type and protection level.
5. Review the specific integration steps. Completing the guide **saves preferences only**; it does not modify Postfix, Exim, ISPConfig or WHM and never claims incoming mail is protected merely because a listener exists.
6. For standalone testing, use **Test an email** and upload a `.eml` message; scanning is advisory and does not capture, deliver or quarantine originals.

## Message reviews

Open **Review mail**, click **Review** beside a message, and read **Why did SpamGate make this decision?**. The system shows human-readable reasons first. Expand the technical section when needed.

An admin may choose **Yes, this was correct** (records an audit confirmation), or **No, this is not spam** (corrects the stored historical classification). Optionally select **Remember this exact sender** to add an enabled, reversible allow rule for the *envelope sender email address*, not an entire domain. This option is intentionally explicit: sender addresses can be forged, and broad exceptions weaken spam filtering. The antivirus rejection override remains in place. Inspect every new exception under **Sender & filtering rules**.

**Review ≠ delivery.** Changing a message's classification does not recall a rejected message or deliver a held original. If SpamGate's SMTP filter retained the original, use the separate **Release held message** action and an upstream relay must be configured. Milter-side quarantine is owned by the mail server and cannot be released through SpamGate's local SMTP quarantine.

The basic review action doesn't automatically teach Bayes or distributed threat feeds: metadata-only history does not contain the full original message. Manual learning controls still exist under Advanced settings.

## Current integration limits

- Postfix: local TCP Milter is the preferred same-host path, but it must be configured on both ends, safely tested and rolled back if needed. `SPAMGATE_MILTER_LISTEN=127.0.0.1:38472` and `SPAMGATE_MILTER_TRUSTED_CIDRS=127.0.0.1/32` enable the local worker; no mail flows through it until Postfix is explicitly configured. Existing Milters must be preserved. ISPConfig-managed settings require panel-safe changes.
- cPanel/WHM: Exim adapter is **not** qualified. Never write its managed Exim configuration directly.
- Exim/custom: raw-message scan API is available, but caller-side verdict enforcement requires a verified connector.
- Remote/Docker: optional. Keep filtering ports private and management access behind HTTPS.

This remains alpha software. Do not put it in a production mail path without MTA interoperability tests, backup/rollback validation, and a build from a supported patched Go toolchain.
