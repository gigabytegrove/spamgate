# SpamGate vs Rspamd: feature gap and acceptance plan

Source of truth: the implemented Go modules and unit/integration tests, not the
presence of a menu label. Rspamd reference: https://docs.rspamd.com/modules/

| Area | SpamGate current state | Acceptance requirement before equivalence |
| --- | --- | --- |
| MTA parity | Milter v2-6 subset, limited Rspamd-compatible HTTP, trusted SMTP relay | live Postfix/Exim traces and failures, queue IDs, per-recipient verdicts, macro handling |
| Authentication | SPF/DKIM subsets, exact-domain DMARC; ARC cryptographic verification under test (no signing/trust) | RFC DKIM fixtures incl. real Gmail/FedEx; organizational DMARC/PSD, cryptographic ARC |
| DNS intelligence | Explicit IPv4 DNSBL zones, disabled by default; validate 127/8 results | safe caches, DNS response semantics, URIBL/SURBL/RHSBL, provider controls and key terms |
| Fuzzy | Local trained near-duplicate SimHash | operator-provided HTTPS JSON fuzzy sources, documented privacy/retention/trust |
| Bayes/neural | Local manually trained classifiers | evaluation sets, drift/poisoning protection, sample-level unlearning and model rollback |
| Content | Basic MIME, words and URL heuristics | robust MIME, archives, phishing impersonation/URL redirect reputation, safe HTML evaluation |
| Antivirus | Optional clamd INSTREAM | ICAP/vendor scanning, MIME/attachment safe limits |
| Dynamic controls | Rules/scores/actions and admin feedback | maps, composites, staged rollback, greylisting, rate limit, reputation, per-domain policy |
| Disposition | Milter hold/reject/tag; new score/scan-ID headers on tags | authenticated release workflow, Dovecot Sieve wizard, per-user routing, subject rewrite policy |
| Observability | Stored scan history, score evidence, basic live mail; DEBUG protocol logs | Prometheus metrics, DNS latency, scan timing, queue-ID correlation, alerts, health and dashboards |
| Management | Native-first UI and standalone binary | public test matrix, upgrade/rollback, secure role model, live MTA qualification |

Prioritize independent authentication correctness and mail safety before
turning on external reputation feeds by default. Keep false-positive-sensitive
modules opt-in until tested on clean mail; do not assume an external fuzzy or
DNSBL source is infallible. For immediate integration, the first acceptance test
is a real Milter scan followed by verified Postfix log correlation and proper
header/hold behavior, **not** merely a socket connection.


See [v1 release gates](V1_RELEASE_GATE.md) for the 0.6.0-alpha.1 authentication, backup and telemetry additions and the full remaining acceptance criteria.
