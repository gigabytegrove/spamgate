# Native Linux systemd adoption and Milter readiness

This is a **deliberately opt-in** installer for the locked native layout:
`/opt/spamgate/spamgate` is the permanent foreground launcher,
`/opt/spamgate/spamgate-worker` is its replaceable child, and
`/opt/spamgate/data` is the persistent state directory. No Docker container,
Postfix restart, Dovecot restart, Postfix configuration rewrite, worker
replacement, or release download is performed by this installer.

## Installation and verification

Run on the mail host after installing both native executables. Preview does
not require root and does not change any file or process:

```bash
python3 scripts/install-native-systemd.py
```

For a stopped native installation, explicitly apply the systemd configuration:

```bash
sudo python3 scripts/install-native-systemd.py --apply
```

If exactly one **manually running** launcher uses the known
`-data /opt/spamgate/data -listen 0.0.0.0:38470` arguments, use this
separate, explicit service-adoption command instead:

```bash
sudo python3 scripts/install-native-systemd.py --apply --adopt-manual
```

The adoption command first stages and validates the service, then sends
SIGTERM to the known launcher and waits for graceful exit. It **never sends
SIGKILL** and refuses to stop a launcher with different arguments. If the new
service fails validation or health checks, it restores the previous unit and
drop-in, returns the old service to its previous active/disabled state, or
attempts to restart the previous manual launcher using its original arguments
and environment. Inspect `manual-recovery.log` under the data directory if
that recovery is needed. As with any live mail-filter transition, use a
maintenance window and watch Postfix deferred mail.

The installer preserves existing `spamgate.service` content if its `ExecStart`
points to the expected permanent launcher. It only creates a new unit when
none exists. It creates or replaces a single drop-in:

```ini
[Service]
Environment="SPAMGATE_MILTER_LISTEN=127.0.0.1:38472"
Environment="SPAMGATE_MILTER_TRUSTED_CIDRS=127.0.0.1/32"
```

The generated unit starts the launcher with
`-data /opt/spamgate/data -listen 0.0.0.0:38470`, enables systemd restart,
and keeps both processes in the same control group. The Milter binds only
localhost, not the public web interface.

After starting/restarting **SpamGate only**, the installer checks:

- the expected worker version through `GET /healthz` on port 38470;
- the **worker-owned** loopback Milter listener on port 38472 via `ss`;
- the systemd service is still active.

Failure rolls back systemd files and service state. This is not a substitute
for a test email through Postfix and a confirmed Dovecot INBOX/Junk delivery.

## Postfix remains the operator's responsibility

Check the *effective* configuration, including hosting-panel overrides:

```bash
postconf -n | grep -E '^(smtpd_milters|non_smtpd_milters|milter_protocol|milter_default_action) ='
postconf -P | grep -i milter || true
ss -ltnp '( sport = :38470 or sport = :38472 )'
systemctl --no-pager --full status spamgate.service
journalctl -u spamgate.service -n 100 --no-pager
```

Both Postfix Milter settings should point to `inet:127.0.0.1:38472`, with
`milter_protocol = 6` on the qualified target. **The installer does not
change `milter_default_action`.** In particular, `tempfail` will defer mail
if the Milter listener is absent or unavailable. Do not change it silently;
verify a designated test mailbox and your site's delivery policy first.

A healthy `/healthz` response proves only the worker HTTP endpoint. A
listening Milter socket proves only listener readiness. Neither proves
successful Milter negotiation, Postfix queue disposition, Dovecot delivery,
mailbox placement, nor zero false positives. See issues #1, #2, #3 and #9
for outstanding live qualification.

## Tests and limitations

```bash
python3 scripts/test-native-systemd.py -v
python3 -m py_compile scripts/install-native-systemd.py
```

The hermetic tests cover preview, clean service installation, existing unit
preservation, manual-adoption refusal and opt-in, health failure, Milter
failure, invalid service, symlink refusal, and rollback. They use a fake
service manager; they **do not** prove a real systemd reboot, mail-host
recovery, or SMTP/Dovecot delivery. Those gates require disposable host
integration and independent production-safe evidence before beta acceptance.
