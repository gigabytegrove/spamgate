# SpamGate 0.4.0-alpha.11: security modules and parity limits

**Standalone testing build, not production qualified.** No automatic changes to Postfix or Dovecot. The integrated Go scanner remains a limited Rspamd alternative, not a drop-in Rspamd replacement. In particular, existing DKIM/SPF/DMARC false-positive reports require independent RFC validation before enforcement can be trusted for unrestricted mail traffic.

## Newly implemented with this build

| Capability | Implementation | Enablement / safety |
| --- | --- | --- |
| IP DNSBL and sender-domain RHSBL and extracted URL-domain URIBL queries | Independently typed DNS reputation zones with score attribution. DNSBL answers must be valid loopback result codes. | Explicit provider configuration, global DNSBL enable; disabled by default. Respect provider terms and query limits. No automatic feed downloads. |
| Visible-link phishing comparison | Bounded, decoded HTML MIME inspection of visible claimed hostname versus actual href destination, with evidence per finding. | Optional checkbox, disabled by default. Does not resolve redirect chains or guarantee phishing detection. |
| Greylisting | Persisted hashed IP/sender/recipient triplet, first tag-level suspicious message deferred, reattempt accepted after configurable delay. | Disabled by default; one-host state only, single timer policy, not Rspamd's full MIME/data hash algorithm. |
| Inbound IP rate limiting | Local per-public-source-IP rolling hour counter persisted to disk; on overage requests Milter temporary failure. | Disabled by default. Shared gateways can cause collateral temporary failures; no authenticated-user exceptions yet. |
| Quarantine vs Junk delivery | Postfix Milter hold request OR `X-Spam` + `X-SpamGate-*` headers for Dovecot Sieve downstream Junk routing. | Default remains Postfix hold. Junk mode requires manually configuring Sieve and verifying delivered mailbox placement. |
| Subject marking | Optional Milter Subject replacement with `[SPAM]` prefix when Postfix negotiates header changes. | Disabled by default. Editing signed Subject headers can break DKIM; use tagging headers instead. |
| Trusted spam headers | Strip incoming `X-SpamGate-*` from untrusted mail before adding SpamGate's own; defer if negotiated Milter capabilities cannot remove forged headers. | Mandatory on Milter path to avoid spoofed junk-routing signals. |
| Reviewed sender-domain reputation | Small bounded score adjustment for a domain after at least four independent human reviews of originally DMARC-authenticated scans. | Disabled by default; no unconditional sender allowlisting; local history, not network trust. |
| Runtime visibility | Dashboard reports enabled/untrained/disabled modules, scan latency, MTA requested action, and temporary policy deferrals. | History records the action **requested**, not verified Postfix queue holding or downstream delivery. |
| Postfix held-mail inventory | Administrator-authenticated, **read-only** `postqueue -j` inspection of actual hold queue; bounded parsing, output and timeout. | Off by default; opt in with `SPAMGATE_POSTFIX_HOLD_INVENTORY=true`; no queue release or modification. |

## How to use safely

On the existing `/opt/spamgate` Linux test machine, launch with web UI on all interfaces and Milter on localhost:

```
SPAMGATE_MILTER_LISTEN=127.0.0.1:38472 \
SPAMGATE_MILTER_TRUSTED_CIDRS=127.0.0.1/32 \
./spamgate -data /opt/spamgate/data -listen 0.0.0.0:38470
```

Optional **read-only** Postfix hold inventory can be enabled by adding `SPAMGATE_POSTFIX_HOLD_INVENTORY=true` to the SpamGate environment. It requires a readable `/usr/sbin/postqueue` command. No sudo escalation is attempted.

If Junk mode is used, configure the Sieve rule in `docs/MESSAGE_TAGGING_AND_JUNK.md`. Simply adding a spam header does **not** itself move mail to Junk. Keep new DNS lists, greylisting, rate limiting, phishing detection, and reviewed reputation disabled until a controlled review confirms correct behavior. Use existing backups and a change window for Milter enforcement.

## What this release is **not**

- Not complete ARC cryptographic validation, public-suffix-aware organizational/PSD DMARC, or independently qualified DKIM/SPF correctness against vendor fixtures.
- Not Rspamd's public or private shared fuzzy servers. Only the pre-existing **local** SimHash learning exists. Remote fuzzy protocol and confidence/storage are not implemented.
- Not automatic SURBL, Spamhaus, DNSBL subscriptions or URL redirect crawling. The configured DNS reputation provider must support the selected query type and permit use.
- Not a robust antivirus multi-engine, archive/macro or ICAP sandbox implementation. Existing optional local clamd capability remains.
- Not Rspamd's full Lua/composites/multimap policy language, multi-tenant policy engine, full per-recipient enforcement, Exim/cPanel parity, Redis clustering or high-availability.
- Not a complete forensic MTA-to-mailbox delivery correlation. `MTAAction` reports **requested** enforcement; explicit queue inspection is needed to verify Postfix holds and Dovecot delivery.
- Not a production security clearance: Windows binaries have not been run on Windows; local build compiler is Go 1.23.2 and no large-scale live traffic / throughput validation was performed.

## Test coverage for this pass

Unit and regression tests cover DNS lookup semantics, allowed versus suspicious phishing links, greylisting persistence and delay, fixed-window rate counts, opt-in reviewed reputation, Milter action and forged-header handling, subject rewriting, and read-only Postfix hold JSON parsing. Run `go test ./...`, `go test -race ./...`, `go vet ./...`, then exercise locally on test mail before enabling mail deferrals.

See `docs/RSPAMD_PARITY_GAPS.md` for the remaining acceptance requirements. **Module presence must not be confused with parity.**
