# Native Milter option-negotiation diagnostic (2026-11-01)

## Contract

Run the deliberately opt-in loopback diagnostic:

    python3 scripts/spamgate-host-probe.py --check-services --verify-milter-protocol --require-milter-actions add_header,change_header,quarantine

The probe connects only to 127.0.0.1 on the selected Milter port (default 38472), sends one Sendmail Milter SMFIC_OPTNEG frame (O), validates a bounded 13-byte reply and closes. Ordinary preflight and --check-services behavior remain unchanged: the latter checks TCP listening only and marks protocol_verified=false.

The request offers version 6, header addition, header change and quarantine action bits, and no skipped callbacks. The reply must be version 2–6, contain only offered actions, and request no skipped callbacks. Incorrect command, length, truncated response, timeout, unsupported version, unoffered actions or protocol shortcuts are failures. TCP acceptance without a valid reply is not protocol readiness.

Use --require-milter-actions only with --verify-milter-protocol. Missing required capabilities fail the check. Optional --expect-version checks /healthz separately. The response records only version and capability booleans, not raw peer bytes.

## Safety and limitations

- No SMTP submission, Milter mail callbacks, Postfix queue commands, Dovecot configuration changes, service restarts or automatic upgrades.
- The connection is loopback, bounded by the existing timeout and closed after negotiation. Malformed lengths are rejected before payload allocation.
- The report distinguishes tcp_listening from protocol_verified and does not include message content, credentials or raw response data.
- This is not proof of the listener's identity, Postfix-to-Milter connectivity, message scanning, hold enforcement or final INBOX/Junk placement.
- A failed optional protocol check prevents any separately opted-in SMTP send. Default preflight never sends SMTP traffic.

## Verification boundary

Python real-loopback regressions cover fragmented replies, valid downgrade, missing capabilities, malformed frames, invalid versions and action flags, early close and no response. CI runs both the parser and host-probe integration suites. Real production Postfix/Dovecot qualification and all cumulative issues #1–#9 remain open.
