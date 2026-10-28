# Guided integration and activation verification

SpamGate is the fixed name of this product and is not configurable.

## What the wizard verifies

1. The admin selects an MTA, installation mode and scoring policy.
2. The wizard explains connector setup. It **does not modify** Postfix/ISPConfig,
   Exim/cPanel, firewall settings or live mail routing.
3. The admin enables a compatible MTA connector on the running SpamGate process.
4. The wizard arms a fresh 20-minute test, gives a unique message subject and
   polls the authenticated readiness API every four seconds.
5. A **new matching message** must pass through that specific connector after
   the challenge starts, with a successful accept or tag verdict. Stale mail,
   simulated scans, manual .eml scans, the wrong connector and rejected messages
   are excluded.
6. The administrator checks that the message reached its destination mailbox
   and explicitly confirms delivery. Only then can the instance be marked
   **running**. This confirmation is recorded by the system as an administrative
   assertion, not independent downstream proof.

This is a per-installation activation gate. Multiple independent installations
carry their own config and verification state; it is not yet an aggregated
multi-instance controller.

## Network binding and Postfix first run

- Web UI: `0.0.0.0:38470` by default; restrict management access to trusted LAN/HTTPS proxy.
- Postfix Milter: `127.0.0.1:38472`, **disabled until explicitly configured** in standalone mode.
- HTTP scanner: port 38471, not an SMTP Milter; it is separate and disabled unless configured.
- Copy/paste Postfix instructions are in [the local setup guide](POSTFIX_LOOPBACK_SETUP.md) and under **Setup guide** in the Web UI. Do not replace existing Milter entries or override panel-managed files.

## Test your existing mail server safely

- **Standalone test**: choose `Just testing` and `Standalone testing`. There
  is no activation or MTA integration; upload saved `.eml` messages to inspect.
- **Postfix / ISPConfig**: configure a trusted loopback Milter listener on
  `127.0.0.1:38472` (`SPAMGATE_MILTER_LISTEN` and
  `SPAMGATE_MILTER_TRUSTED_CIDRS=127.0.0.1/32`). Review existing Postfix
  `smtpd_milters` before adding `inet:127.0.0.1:38472` by your mail server's
  supported configuration mechanism. **Never overwrite an existing Milter.**
  ISPConfig may regenerate Postfix configuration; do not directly modify its
  files outside a verified panel-safe approach.
- **Custom connector**: select `Other mail server`; use SpamGate's private
  Rspamd-compatible HTTP scanner port, currently mapped as `rspamd-http` in
  recorded message history. The caller must implement verdict enforcement.
- **Exim / cPanel**: native adapter is not yet qualified. Live activation is
  intentionally blocked. Choose standalone testing, not a purportedly running
  mail-security instance.

The real test must travel through the MTA, not through the management UI scan
workbench. A listening port only establishes configuration; the verified
subject demonstrates a processing event, **not** external connectivity or
reliable delivery. Keep Rspamd or other production filters enabled until your
integration passes independent testing and rollback validation.

### Relevant management API (admin-only; CSRF required for state changes)

- `PUT /api/v1/onboarding` — save selected setup preferences (never activates)
- `GET /api/v1/setup/readiness` — listener and challenge state, verified
  connector evidence, and effective running status
- `POST /api/v1/setup/monitor` — arm or restart a one-time 20-minute challenge
- `POST /api/v1/setup/activate` with
  `{ "delivery_confirmed": true }` — activate **only after** an accepted/tagged
  challenge has been observed on the chosen connector and the user has checked
  the destination mailbox

No install scripts are required for a portable standalone evaluation. Production
interoperability, final-delivery validation and release-signing remain separate
qualifications.
