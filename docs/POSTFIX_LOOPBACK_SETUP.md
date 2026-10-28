# Postfix + standalone SpamGate on the same Linux machine

The Web UI binds **0.0.0.0:38470**. The Milter should bind **127.0.0.1:38472** only. Port 38471 is **HTTP scanning, not Milter**. Do not change Postfix before confirming SpamGate is listening locally.

## 1. Start SpamGate (foreground, no installation)

From the extracted ZIP in `/opt/spamgate`:

```bash
cd /opt/spamgate
SPAMGATE_MILTER_LISTEN=127.0.0.1:38472 \
SPAMGATE_MILTER_TRUSTED_CIDRS=127.0.0.1/32 \
./spamgate -data /opt/spamgate/data -listen 0.0.0.0:38470
```

This creates **no** service, installer, or Postfix modifications. Verify the listener before enabling fail-closed mail routing:

```bash
sudo ss -ltnp | grep -E ':(38470|38472)\b'
```

Open `http://MAIL_SERVER_LAN_IP:38470` from a trusted machine. Restrict access to TCP 38470 by firewall; do not expose plaintext administration on the Internet.

## 2. Configure Postfix's two mail paths

For **Postfix without any other Milters** in `/etc/postfix/main.cf`:

```ini
smtpd_milters = inet:127.0.0.1:38472
non_smtpd_milters = inet:127.0.0.1:38472
milter_protocol = 6
milter_default_action = tempfail
```

**If Milters already exist, append** `inet:127.0.0.1:38472` separated by a comma and keep all existing entries. Check `postconf -n` and `postconf -P` for overrides. **ISPConfig / cPanel / Plesk:** do not directly alter panel-managed mail configuration; use a verified, panel-supported persistence mechanism.

With `milter_default_action = tempfail`, an unavailable filter temporarily defers mail; do not enable it before verifying the socket.

```bash
sudo postfix check
sudo postfix reload
postconf -n | grep -E '^(smtpd_milters|non_smtpd_milters|milter_protocol|milter_default_action) ='
postconf -P | grep -i milter || true
```

## 3. Verify actual mail reaches SpamGate

Go to **Setup guide** in SpamGate, select **Postfix → On this mail server**, and use **Start monitoring incoming mail**. Send a fresh message with the generated subject *through Postfix*. A direct `.eml` upload does not count. The wizard shows the observed connector and verdict; confirm the test appears in the recipient inbox before marking the connection running.

If mail is delivered without a SpamGate event, inspect the Postfix log and service-level overrides (`postconf -P`), the SpamGate process output, and the effective `milter_default_action`. A listening socket alone does not prove real mail is being scanned.

**Not production-certified:** alpha protocol support has not been qualified on all Postfix builds and operating systems. Keep a tested rollback route and your existing spam protection until that qualification is complete.
