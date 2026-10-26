# SpamGate exhaustive capability plan

**Product goal:** a self-hosted, production-grade, cross-platform replacement for Rspamd that preserves protocol interoperability while providing a materially better admin and mailbox-user experience. Scope here is committed design intent, **not a claim that the features exist**. Status follows verified code: `DONE` means present in this alpha, `NEXT` is a planned release milestone, `LATER` requires further architecture/research.

## 1. Engine, transparency and rule authoring

| Feature | Status |
|---|---|
| RFC 5322 message intake, limited MIME parts, built-in header/text/URL/attachment heuristics | DONE |
| Per-message symbol, source/list, evidence, weight, score and action | DONE |
| Editable numeric action thresholds, weighted rules and force-action overrides | DONE |
| Match by sender/domain/recipient/IP/subject/body/URL-domain/header text | DONE |
| Custom DNSBL provider zones, disabled by default | DONE |
| Rule enable/disable/edit, priorities, expiry and dry-run/test mode | NEXT |
| Per-domain, per-tenant, per-mailbox and group policies | NEXT |
| Structured policy conditions (AND/OR/NOT, header selectors, regex with time limits) | NEXT |
| Correlated composite symbols and exclusion rules | NEXT |
| Per-recipient verdicts, quarantine policies and SMTP transaction splitting | NEXT |
| Built-in detector scoring overrides and enable/disable management | DONE |
| Full RFC 7208 SPF / RFC 6376 DKIM / RFC 7489 DMARC / RFC 8617 ARC | NEXT (SPF/DKIM + exact-domain DMARC subsets implemented; ARC outstanding) |
| Envelope validation, Received-chain trust, HELO/FQDN/MX/PTR consistency, DNSSEC awareness | NEXT |
| MIME robustness, attachment/content disarm, archive recursion limits, signature detection | NEXT |
| URI/domain/IDN homograph and phishing heuristics, URL shortener expansion, safe URL reputation | NEXT |
| DNSBL/RHSBL/SURBL/URIBL, allowlists, private provider credentials, safe caching | NEXT |
| Spam traps, disposable domains, age/reputation, per-ASN/country/location intelligence | NEXT |
| Greylisting and rate limits (IP/sender/recipient/domain), retry compliance and backoff | NEXT |
| Bayesian/Naive Bayes classifier with user-level ham/spam learning | NEXT (persistent global training and admin UI implemented; user-level corpora and unlearning pending) |
| Fuzzy hashes, similarity graph, recurrent-campaign correlation | NEXT |
| Optional neural/ML and configurable model backends without cloud dependency | NEXT |
| Antivirus integrations (ClamAV, ICAP, vendor APIs) | NEXT (ClamAV INSTREAM implemented; ICAP/vendors outstanding) |
| Rules-as-code import/export, signed rulesets, versioning, staged rollout, rollback | LATER |
| Rule package marketplace/community feeds with trust/expiry/reputation | LATER |

## 2. Integrations and portability

| Feature | Status |
|---|---|
| Go single binary for supported Go targets, embedded Web UI | DONE |
| Authenticated HTTP raw-message scan protocol | DONE |
| Trusted SMTP intake and onward authenticated TLS relay | DONE |
| Milter (Postfix / Sendmail), TLS and local socket transport | NEXT (Milter TCP wire subset implemented; TLS, socket + live qualification outstanding) |
| Exim ACL/spamd, Postfix policy and after-queue content-filter setup | NEXT |
| SMTP PIPELINING, STARTTLS, DSN, SMTPUTF8, CHUNKING/BDAT, LMTP | NEXT
| Trusted MTA `XFORWARD ADDR` with separate receiving peer provenance | DONE |
| Exchange Server transport adapter / Windows service / event log | NEXT |
| Exchange Online and Microsoft 365 approved connector / tenant permissions | LATER |
| MailEnable, SmarterMail, hMailServer, OpenSMTPD, Haraka, Dovecot/Sieve adapters | NEXT |
| Custom webhook, gRPC, documented SDK for Go, .NET, Java, Python and Rust | NEXT |
| Rspamd `/checkv2` and milter compatibility mode with migration tests | NEXT (HTTP/Milter subsets implemented; full parity not validated) |
| Rspamd maps/scores import, equivalence preview and migration rollback | NEXT |
| Multi-MTA routing pools, connection pooling and failover | LATER |

## 3. User experience, audit, analytics and quarantine

| Feature | Status |
|---|---|
| First-run installation wizard, responsive operations console and admin navigation | DONE |
| Historical verdict log, scores and detailed rule/list provenance | DONE |
| Action counters, score average, up to 1,000 visible messages, JSONL export | DONE |
| Admin decision reclassification with reason, audit findings | DONE |
| SMTP quarantine storage and manual upstream release | DONE |
| Self-service manually managed exact-mailbox accounts, per-sender overrides | DONE |
| Deep multifield history search, pagination, saved filters and export scheduling | NEXT |
| Dashboards: time trends, decision rates, false-positive/negative feedback, SLA charts | NEXT |
| Rule hit-rate and effectiveness, trend regression and scoring drift | NEXT |
| Live traffic stream, health probes, connector status, response time histograms | NEXT |
| Quarantine expiry, delete/restore, search, safe preview with sanitized HTML | NEXT |
| Digest emails, user release requests, shared mailbox moderation, approval workflows | NEXT |
| One-click learn ham/spam, mailbox-specific and global feedback training | NEXT |
| Role permissions (admin/operator/auditor/support/user), SSO/OIDC/MFA/passkeys | NEXT |
| LDAP/AD/IMAP login with aliases and group mapping | LATER (deferred) |
| In-console integrations wizard with MTA autoconfiguration diagnostics | NEXT |
| Internationalization, accessibility audit and keyboard-first workflows | NEXT |
| Bulk rule changes, staged/diff preview, undo and audit trail | NEXT |
| Search/export retention policies and privacy/PII redaction | NEXT |
| Custom views, reports, dashboards, notifications and webhook alerts | LATER |

## 4. Production engineering, deployment and resilience

| Feature | Status |
|---|---|
| No Node.js or database required for alpha binary; durable single-node journal | DONE |
| Docker Compose and multi-stage Go build recipe | DONE |
| Admin first-run claim key, no default credentials, secure sessions and CSRF | DONE |
| Container health/liveness check, structured logs, process shutdown | DONE |
| Durable transactional SMTP spool, dedupe, retry scheduler, DLQ and delivery receipts | NEXT |
| SQLite durable option, migrations, online compaction, hot backups, encryption controls | NEXT |
| Postgres clustered option, Redis cache, horizontal workers and queue replication | LATER (deferred) |
| Atomic policy snapshot, concurrent write controls, imported rules consistency | NEXT |
| Automated SMTP interoperability suites (success/reject/tempfail/retry/multi-RCPT) | NEXT |
| SMTP/LMTP/Milter protocol fuzzing and MIME parser mutation corpus | NEXT |
| Built-in updater: stable/beta/alpha, compatibility checks, rollback | NEXT |
| Windows service package, signed macOS builds and Linux packages for common distros | NEXT |
| Container image multi-arch release and SBOM/signature/provenance | NEXT |
| Prometheus/OpenTelemetry metrics, trace sampling and failure alerts | NEXT |
| Secrets management, encryption-at-rest, rotation, credentials/test connections | NEXT |
| Continuous threat-model review, penetration tests and vulnerability advisories | NEXT |
| Mail cluster scale tests, soak tests, incident playbooks, disaster recovery exercise | LATER |
| Air-gapped installations, precompiled offline packages and controlled feed updates | LATER |
| Policy templates and safe production migration from Rspamd with canary rollout | LATER |

## Release acceptance gates

- **Alpha:** unit/integration tests, first-run claim flow, limited API/SMTP smoke coverage; never advertised as equivalent to production Rspamd.
- **Beta:** SMTP/Milter/Exim integration tested; SPF/DKIM/DMARC checked against public test vectors, durable queue, quarantine retention and role/alias security. Connector compatibility matrix records exact upstream versions tested.
- **1.0 production:** parity matrix validated against Rspamd for production-essential actions and security features; complete operational docs, configuration migration, restore tests, repeatable load benchmarks, independently reviewed vulnerabilities, signed release artifacts and no data-loss bugs known.

**Licensing decision:** owner must choose and publish a project license before promoting public contributions or claiming open-source redistribution rights. Until then, no license is granted by default.
