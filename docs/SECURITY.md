# Security posture — important for alpha deployments

This project handles sensitive email metadata and, for SMTP quarantine, complete original messages. Treat it as a security-sensitive server. **Alpha does not mean safe for exposed public mail flow.**

## Implemented safeguards

- No default admin password, no demo login; first setup requires a random 256-bit claim key printed only to application logs.
- Administrator passwords salted and derived using PBKDF2-HMAC-SHA256 with 250,000 iterations; verification uses constant-time comparison.
- Scan/API keys generated from cryptographic randomness and SHA-256 hashed at rest; keys may be revoked and are only returned once.
- Sessions use random HttpOnly SameSite=Strict cookies, 12-hour expiry, per-session CSRF, origin checks, and basic per-client-IP login throttling.
- Content Security Policy, clickjacking mitigation and nosniff/referrer protections on HTTP responses; frontend prints dynamic data with HTML escaping.
- SMTP only starts with an outbound relay, a non-empty trusted-client CIDR list and a non-empty explicit recipient-domain list; no untrusted default relay.
- SMTP AUTH credentials may not be transmitted on `SPAMGATE_RELAY_TLS=none`; outbound TLS uses verified server names and TLS ≥1.2.
- Storage files are created with private permissions (`0600` files, `0700` directories), and full originals are retained only for SMTP quarantine.
- Built-in DNSBL queries are disabled by default; service never queries a provider merely because it appears as a default example.

## Known limitations — do not ignore

1. **Do not use as a public-facing MX.** The inbound filter does not implement STARTTLS, SMTP AUTH, modern SMTP extensions or hardened abuse controls. Put a fully supported MTA in front of it on a trusted private network.
2. **The web interface is HTTP.** Place behind a trusted HTTPS reverse proxy and set `SPAMGATE_SECURE_COOKIES=true` before public access. The app does not validate proxy forwarded headers.
3. **Authentication and threat detection are incomplete.** Limited SPF, cryptographic DKIM and exact-domain DMARC checks are implemented; ARC and organizational-domain DMARC discovery are missing. Optional ClamAV INSTREAM and a locally trained Bayesian classifier are present, but full antivirus orchestration, phishing feed APIs, fuzzy detection and neural scoring are not. DNS/DKIM vectors and cross-MTA interoperability need additional qualification. Scores must not be considered an adequate standalone production spam verdict.
4. **No transactional SMTP delivery queue.** The relay path is synchronous. End-to-end delivery, retry and crash safety require further work and testing.
5. **History eviction attempts to delete matching quarantine blobs; this is not transactional.** Monitor and manually remediate deletion failures, orphan files and any external backups to meet mail-privacy requirements.
6. **Local JSONL storage has single-writer semantics.** Do not mount one store concurrently from multiple replicas. Interrupted or damaged event logs may stop startup; restore from backup as needed.
7. **Mailbox identities are local.** Mail server directory authentication, signed mailbox verification, alias and group authorization, OIDC/MFA and delegated administration are not yet implemented.
8. **SMTP, Milter and Rspamd HTTP clients are network trusted.** Use narrow `/32` or `/128` ranges, firewalls and network segmentation. A broad trusted LAN range can permit unwanted injection. Their listeners have no native TLS; never expose them on an untrusted network.
9. **Scanned bodies are not persisted for HTTP or Milter scans.** External clients implement enforcement and quarantine in their own MTA; admins cannot release HTTP-scan-only messages.
10. **A mail relay loop is possible if misconfigured.** Never set the outbound SMTP relay to point to SpamGate itself.
11. **Bayesian training can retain sensitive tokens.** The `bayes.json` classifier stores vocabulary derived from user-submitted messages, not raw mail, but that vocabulary can contain identifying text. Restrict access and include it in private backups; unlearning and privacy deletion workflows are not implemented.

## Reporting vulnerabilities

Do not file exploitable secrets or private customer email in public issue reports. Use GitHub's private vulnerability reporting channel if enabled for the repository, or contact the repository maintainers through a confidential channel agreed with them. Scrub logs before sharing.

## Planned security gates for production

Independent protocol fuzzing, MIME parser limits review, outbound queue integration tests, load tests, chaos testing, external dependency audits, migration/backup recovery tests, key rotation, MFA/OIDC, structured admin audit logs, mail-specific PII scrubbing, envelope/header spoofing cases, RFC conformance tests, and integration certification for each supported MTA family.
