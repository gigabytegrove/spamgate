# Native LMTP listener wire verification — 2026-11-01

This opt-in, read-only check advances issues #1, #6 and #9. It complements (does not replace) the Dovecot LDA/LMTP Sieve **configuration** verifier. The native SpamGate launcher, worker, persistent data and Milter ports remain unchanged.

Unix socket (default when the flag is present):

~~~bash
python3 scripts/spamgate-host-probe.py --check-lmtp-listener
python3 scripts/spamgate-host-probe.py --check-lmtp-listener --lmtp-socket /run/dovecot/lmtp
~~~

Explicit IPv4 loopback TCP listener:

~~~bash
python3 scripts/spamgate-host-probe.py --check-lmtp-listener --lmtp-tcp-port 24
~~~

No LMTP listener is contacted without `--check-lmtp-listener`. The Unix socket must be an absolute, existing socket (not a symlink), with a path of at most 107 encoded bytes. The TCP option always connects to **127.0.0.1**; hostnames, remote addresses, and DNS resolution are not supported. The operator selects the endpoint from independently inspected Dovecot/Postfix configuration; the diagnostic does not infer it.

The probe verifies a bounded **220 greeting → LHLO → 250 multiline capabilities → QUIT → 221** exchange. It never sends MAIL, RCPT, DATA, AUTH or STARTTLS. It accepts at most 512 bytes per line, 8 KiB per reply, 32 lines and an eight-second total protocol deadline, with a three-second per-I/O timeout. Only allowlisted capability names and status/error classes appear in JSON, not server banners, authentication details or raw replies. Malformed, oversized, truncated, mixed-code and failed-QUIT responses fail closed. If combined with an explicitly requested SMTP test, failure prevents SMTP submission.

This is **listener handshake evidence only**. It does not prove the listener belongs to Dovecot, that Postfix routes to it, that LMTP delivery succeeds, that Sieve executes, that mailbox placement is correct, or that ISPConfig preserves configuration. A TCP listener that deliberately emulates LMTP can pass. No production host was contacted.

The regression suite exercises real loopback TCP and Unix socket servers, command capture proving only LHLO/QUIT were sent, framing and timeout attacks, privacy redaction, invalid endpoint arguments, CLI opt-in and failure gating. CI executes the suite alongside existing native host and Postfix/Dovecot lab tests. Real authorized host routing and mailbox evidence remain mandatory for beta qualification.
