# Detection engines — implementation inventory

The engine MUST preserve the source and numerical weight of every verdict. The following inventory distinguishes working checks from unsupported aspirational modules.

| Engine | Current state | Evidence available | Remaining before parity |
|---|---|---|---|
| SPF | **Working limited implementation** | Envelope domain, DNS mechanism, result | RFC macro expansion, `ptr` policy, DNS timeout/error vector suite, HELO from every connector |
| DKIM | **Working limited verification** | Signature result, selector, signed domain, algorithm | More RFC vectors, signing-policy tags, all canonicalization edge cases, test with real MTAs |
| DMARC | **Exact-domain subset** | Policy, From domain, SPF/DKIM alignment | Public suffix aware organizational fallback, subdomain policy, PSD DMARC, detailed aggregate reporting |
| ARC | **Not implemented** | None | Full RFC 8617 chain validation, sealer and trust policy |
| Bayesian learning | **Not implemented** | None | Train/retrain UI, mailbox/global corpora, ham/spam rollback, poisoning protection and decay |
| Fuzzy matching | **Not implemented** | None | Local fingerprint store, hash similarity, clustering, expiry and distributed exchange |
| Neural scoring | **Not implemented** | None | Optional on-prem inference model with strict latency and CPU budgets, management UI and feature provenance |
| Antivirus | **ClamAV INSTREAM implemented, optional** | Malware signature and forced rejection | ICAP/vendor integrations, archive policies, deeper MIME attachment extraction, malware event analytics |
| URL/DNSBL | **Limited built-ins** | Explicit URL/DNSBL source | RHSBL/URIBL/SURBL, response code semantics, safe DNS query cache |
| Rspamd HTTP | **Subset implementation** | Named symbol list in compatibility JSON | `/checkv3`, flags/controller parity, uncompressed/compressed body transforms |
| Milter | **Wire-compatible tested subset** | Message history, SMTP-level verdict | Live Postfix/Sendmail certification, broader actions/macro support |

**Deployment gate:** This is an alpha capability set. Keep Rspamd in the mail path until integration tests, RFC regression vectors, load tests, and rollback procedures for the specific MTA have been demonstrated. MTA response handling and error behavior must be verified rather than assumed.

## Scope order

1. Protocol parity: Postfix and Sendmail Milter fixtures and real mail-server tests, Rspamd HTTP golden traces; complete required Rspamd response formats.
2. Authentication: SPF/DKIM RFC vectors, production-grade DMARC organizational discovery, ARC verification and signatures.
3. Learning and intelligence: persistent Bayes training, fuzzy signatures, optional neural inference, anti-poisoning controls.
4. Threat detection and safety: ClamAV and ICAP handling, archive limits, fail policies, asynchronous reporting and safe quarantine.
5. Large-scale deployment: multi-node replication and enterprise directory connectors. **Deferred.**
