# Detection engines — implementation inventory

The engine MUST preserve the source and numerical weight of every verdict. The following inventory distinguishes working checks from unsupported aspirational modules.

| Engine | Current state | Evidence available | Remaining before parity |
|---|---|---|---|
| SPF | **Working limited implementation** | Envelope domain, DNS mechanism, result | RFC macro expansion, `ptr` policy, DNS timeout/error vector suite, HELO from every connector |
| DKIM | **Working limited verification** | Signature result, selector, signed domain, algorithm | More RFC vectors, signing-policy tags, all canonicalization edge cases, test with real MTAs |
| DMARC | **Exact-domain subset** | Policy, From domain, SPF/DKIM alignment | Public suffix aware organizational fallback, subdomain policy, PSD DMARC, detailed aggregate reporting |
| ARC | **Structure-only diagnostics** | Triple completeness, numbering, claimed cv status (weight zero) | Cryptographic AMS/AS verification, sealing and trust policy |
| Bayesian learning | **Local classifier and admin training UI implemented** | Probability, class count, feature vocabulary size | Sample-level unlearning, rollback, poisoning protection, decay, mailbox corpora and evaluation suite |
| Fuzzy matching | **Local trained SimHash implemented** | Similarity, sample ID, class, 90-day retention | Distributed Rspamd fuzzy protocol, feature tuning, robust false-positive evaluation |
| Neural scoring | **Manual symbol-based neural classifier implemented** | Class probability, training counts, symbol features, admin feedback | Drift detection, rollback/retrain, model evaluation, compatibility with Rspamd KANN models |
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

### Bayesian learning safety and privacy

The administrator can upload manually confirmed spam or ham .eml samples in **Spam learning** or use `POST /api/v1/bayes/train?label=spam` / `label=ham` with an authorized admin session and CSRF protection. The on-disk `bayes.json` file persists word vocabulary and document frequencies (it does not store original message bodies). Treat this file as sensitive: **vocabulary terms can themselves contain personal information.** It is held in the protected application data directory and should be backed up alongside `config.json`. Classifier effects are disabled until at least 10 confirmed spam and 10 confirmed ham samples exist. Scores from the model are part of the historical findings, and the weights can be managed under **Built-in signals**. There is no automatic feedback training; only explicitly authorized administrators can mutate the corpus.
