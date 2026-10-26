# Protocol listeners and port isolation

SpamGate uses four **distinct** listeners. Defaults are chosen to reduce accidental collisions with other mail software; they are unregistered TCP ports and can still be occupied by another program. All bind addresses are configurable. The process stops on listener-bind failure. Never point public SMTP traffic directly at the Milter or HTTP scan port.

| Service | Port | Enablement | Access control | Enforcement |
|---|---:|---|---|---|
| Web UI + management API | **38470** | Always enabled (`-listen`) | Admin login/session or scoped API token | API returns advisory results; web actions require authentication |
| Rspamd-style HTTP worker | **38471** | Set `SPAMGATE_RSPAMD_LISTEN` | `SPAMGATE_RSPAMD_TRUSTED_CIDRS`, optional `SPAMGATE_RSPAMD_TOKEN` | Returns verdict to caller; caller applies action |
| Milter worker | **38472** | Set `SPAMGATE_MILTER_LISTEN` | Mandatory `SPAMGATE_MILTER_TRUSTED_CIDRS` | Reject, MTA-side quarantine, or header addition over Milter protocol |
| SMTP content filter | **38473** | Set `SPAMGATE_SMTP_LISTEN` plus upstream relay configuration | Mandatory `SPAMGATE_SMTP_TRUSTED_CIDRS` and accepted domains | Relays accepted mail, rejects spam and holds quarantine |

Do not reuse the Web UI listener for an MTA integration. For remote exposure prefer firewalled dedicated VLAN or internal Docker networks. Management must sit behind HTTPS with `SPAMGATE_SECURE_COOKIES=true`. Filtering listeners do **not** provide TLS themselves. Never expose these raw endpoints directly to the internet. Bind to an interface accessible only to a trusted MTA or use an authenticated network tunnel.

### Rspamd-style HTTP request

```
POST /checkv2 HTTP/1.1
Host: mailfilter.internal:38471
IP: 198.51.100.20
From: sender@example.net
Rcpt: user@example.org
Helo: relay.example.net
Content-Type: message/rfc822

<raw RFC 5322 message>
```

Implemented: `/checkv2`, `/check`, `/symbols`, `/scanv2` as POST; `/ping` as GET. Responses include `score`, `required_score`, `action`, `thresholds`, named `symbols` with score/options/source provenance, `message-id`, and SpamGate `scan_id`. HTTP clients must enforce the action themselves. A verified authenticated management user does not automatically receive MTA access, and a trusted MTA does not automatically receive admin permissions.

**Not fully compatible:** Rspamd `/checkv3`, `body_block`, zstd compression, dynamic scan settings, advanced milter header mutation, Redis-backed commands, controller endpoints, `/learnspam`, `/learnham`, fuzzy endpoints, additional Rspamd reply fields, and unsupported flags remain outside the current wire contract. Do not claim universal drop-in HTTP compatibility until the compatibility matrix passes against real Rspamd and supported MTA clients.

### Milter

Milter v2–v6 binary framing is implemented with option negotiation capped at version 6, 64 KiB maximum frame, 10 MiB complete message, a 64-connection cap, peer-CIDR enforcement, 120-second per-connection read/write deadline, and persistent event history. It handles connection/HELO/envelope/header/body/end-of-message callbacks, macros (ignored safely), abort, and reuse of a connection for multiple transactions.

Implemented end-of-message actions: `r` reject, `h` add `X-Spam: Yes` on tag, `q` MTA quarantine request, `c` continue. If MTA does not offer required capability (header addition or quarantine), the filter responds `t` temporary failure rather than silently accepting a message that should have been changed or held. Store or scan failures also temporary-fail. Milter SMTP policy applies inside the sending MTA; SpamGate does not retain the Milter message original for local quarantine.

**Not yet full parity:** Milter macro-derived authentication metadata, per-recipient multi-verdict splitting, ESMTP body replacement, custom rejection text, modification of existing headers, dynamic symbol lists, TLS-native Milter and Unix-domain socket listener, performance benchmarks, and a live Postfix/Sendmail qualification matrix.

### SPF, DKIM, DMARC and antivirus

- SPF: real envelope-based DNS SPF mechanisms (`all`, `ip4`, `ip6`, `include`, `a`, `mx`, `exists`, `redirect`), bounded recursive lookups, loop detection. Does not yet support SPF macros or deprecated `ptr`; treats these as permission errors rather than false passes.
- DKIM: cryptographic `rsa-sha256` and `ed25519-sha256` verification, simple/relaxed header/body canonicalization, signed-header selection, body digest, DNS public key lookup, expiration check. RSA-SHA1 deliberately unsupported. Some optional signing policy tags are not enforced yet.
- DMARC: `v=DMARC1` exact-header-From-domain TXT discovery, `p`, `adkim`, `aspf`, aligned SPF or DKIM evaluation. No organizational-domain/public-suffix discovery or PSD DMARC yet; does not independently force SMTP policy enforcement.
- ClamAV: set `SPAMGATE_CLAMAV_ADDRESS=unix:///run/clamav/clamd.ctl` or `tcp://clamd.internal:3310` for the clamd INSTREAM protocol. Virus detections force a reject; service errors fail scanning closed. The ClamAV connection must be internal/private. No ClamAV daemon is bundled in the image.

These mechanisms produce detailed evidence in the message inspector; DNS/service errors and unsupported cases must not be represented as authenticated passes.

### Collision and container networking

Host publication in `compose.yaml` is intentionally limited to port 38470. To enable mail services, uncomment only the needed `ports` mapping and corresponding environment variables and specify a trusted address/CIDR. When changing the internal listener port, update BOTH the listen environment variable and the container port in its mapping. Check host availability with `ss -lnt` (Linux) or `netstat -ano -p tcp` (Windows) before starting. Never edit an existing mail server's live Milter settings until a dedicated integration test confirms correct responses on the new port.

### Learning service

The authenticated Web UI on port **38470** includes **Spam learning**, with `GET /api/v1/bayes/stats` and `POST /api/v1/bayes/train?label=ham|spam` (raw `.eml` body). Training is admin-only and protected by CSRF for browser sessions. The classifier is stored at `bayes.json` within the SpamGate data directory; this is not a separately bound TCP service.
