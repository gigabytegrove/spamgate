# Read-only native Postfix Milter configuration evidence (2026-11-01)

Run `python3 scripts/spamgate-host-probe.py --check-postfix-config` to inspect Postfix without sending a message or changing any configuration. The default probe remains entirely unchanged. Combine with `--check-services --verify-milter-protocol` to require the separate loopback protocol check.

The opt-in check executes only `postconf -h` for `smtpd_milters`, `non_smtpd_milters`, `milter_protocol`, and `milter_default_action`, and `smtpd_milter_maps`, followed by `postconf -P` to identify master.cf service overrides. It does not invoke `postconf -e`, `postfix reload`, `postsuper`, or any delivery command. Each command has a five-second timeout, bounded response, and no shell interpolation. Raw configuration values and potential secrets are never returned.

A passing SMTP configuration snapshot requires exactly one `inet:127.0.0.1:38472` endpoint in `smtpd_milters`, no additional unreviewed Milter chain members, protocol version 2–6, `milter_default_action=tempfail`, and no service-specific Milter overrides or dynamic `smtpd_milter_maps`. Other settings or ambiguous expressions require explicit operator review; the probe does not modify them. Local non-SMTP submission coverage is reported separately.

This is a **configuration-only** gate. It cannot prove Postfix has reloaded the configuration, that every master.cf service uses it, that Postfix enforces Milter actions, that a message is durably accepted, or that Dovecot places mail in INBOX/Junk. A passing check must not be represented as host qualification. If combined with `--send`, any failed configuration check prevents SMTP submission.

Tests use a fake read-only `postconf` executable and pure parser fixtures. They exercise safe/missing/duplicate Milter endpoints, chain ordering, failure-action policy, version validation, service overrides, malformed output, unavailable executables, and send suppression. Production host evidence and all nine cumulative beta gates remain open.
