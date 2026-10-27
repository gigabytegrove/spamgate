# Mail server and operating-system compatibility

SpamGate's goal is OS-independent compatibility. The **protocol boundary**, not an OS agent, determines support. An SMTP content-filter chain or an authenticated HTTP client can be implemented on Linux, Windows, macOS, BSD or custom systems. These are architectural capabilities, **not a claim of verified native integration with all MTAs**.

| MTA / platform | Alpha connection route | Native integration status |
| --- | --- | --- |
| Postfix / Linux, BSD | Approved Postfix instance can route a dedicated SMTP content-filter transaction to SpamGate | SMTP filtering and TCP Milter subsets available; neither qualified against a live Postfix instance |
| Exim / Linux, BSD | Separate SMTP routing or custom HTTP scanner integration | Native ACL / spool protocol planned |
| Sendmail | SMTP routing or TCP Milter | Milter v2–v6 subset implemented; no live Sendmail qualification |
| OpenSMTPD | MTA-controlled SMTP route or custom connector | Native filter API planned |
| Haraka / Node.js | Plugin invoking raw HTTP scan API | First-party plugin planned |
| Dovecot / IMAP/Sieve | Filtering via upstream MTA before delivery | Native mailbox/quarantine integration planned |
| Microsoft Exchange Server / Windows | Custom transport adapter or permitted mail-flow SMTP route | Native transport agent planned; no certification |
| Exchange Online / Microsoft 365 | Connector/service path subject to cloud mail-flow policy | Native integration and tenant authorization planned |
| hMailServer / Windows | SMTP routing or extension calling HTTP API | Adapter planned |
| MailEnable / Windows | SMTP routing or programmatic connector | Adapter planned |
| SmarterMail / Windows | SMTP routing or API integration | Adapter planned |
| macOS / custom SMTP services | SMTP route or custom HTTP connector | Supported by protocol design; no vendor adapter certified |
| Custom Go, Rust, .NET, Java, Python mail server | Send RFC 5322 bytes to authenticated HTTP endpoint and enforce verdict | HTTP contract implemented now |
| Third-party filtering gateway | Private trusted SMTP handoff | Depends on specific product configuration, not pre-certified |

## Protocol targets

- HTTP request/response scanning contract for custom systems — **implemented** on management API port 38470 (authenticated) and separately on MTA-worker port 38471 (trusted peers).
- SMTP inbound filter from approved clients + outbound relay — **implemented with limited ESMTP**.
- Rspamd-style HTTP `/checkv2`, `/check`, `/symbols`, `/scanv2` — **implemented subsets** on dedicated port 38471. Request/response parity with all Rspamd options is **not established**.
- Sendmail-compatible **TCP** Milter v2–v6 subset — **implemented**, with negotiated add-header, reject, quarantine and temporary failure. UNIX socket mode, extended mutation actions, and live MTA certification are **not implemented**.
- LMTP proxy and verdict hooks — **not implemented**.
- Exim native ACL/spamd response protocol — **not implemented**.
- Postfix policy protocol and after-queue re-injection templates — **not implemented**.
- Webhook scanning, gRPC, Unix-domain local filter, streaming SMTP/BDAT — **not implemented**.
- Mailbox identities over OIDC/LDAP/IMAP authentication — **not implemented**.

A supported email-user override requires reliable identity binding to recipients and knowledge of aliases/shared mailboxes. The alpha supports manually created users for exact mailbox addresses only. Multi-recipient transactions do not apply per-user forced rules unless every recipient is the same permitted mailbox.

## Native-first installation status

The primary installation is a local Go binary/systemd daemon on a pre-existing mail server, **not Docker**. [Native mail-server deployment](NATIVE_MAIL_SERVERS.md) distinguishes qualified protocol subsets from hosting-panel-native integration. Unmanaged Postfix has a guarded opt-in Milter attachment script. ISPConfig-managed Postfix requires panel-safe manual persistence. cPanel uses Exim; an automatic WHM-compatible adapter remains outstanding. Docker is optional.
