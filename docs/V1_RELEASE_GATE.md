# v1.0 release-readiness checkpoint — 0.6.0-alpha.1

**Exim/cPanel integration has been explicitly deferred out of this v1 target.**
It must not appear as a release blocker for the Postfix-focused milestone.

## Implemented and tested in this engineering pass

- ARC: RFC 8617 chain structural requirements, newest AMS RSA signature and
  all AS seal signature verification. Independently generated RSA fixture and
  body/AAR tampering regressions. Score remains zero; no trust or signing.
- External fingerprint reputation: optional HTTPS-only, no redirects, no raw
  message content, 800 ms deadline, bounded response and high-confidence threshold.
  Separate protocol from Rspamd fuzzy. No server/provider shipped.
- MIME/ZIP: MIME content decoding, executable magic detection, ZIP metadata
  and member inspection, encrypted-entry information, expansion checks, bounded
  depth/size and +10 score cap. Not full malware/attachment decoding.
- Threat snapshot: admin-managed local file with freshness/expiry/source,
  IP/domain indicators, strict input/size/entry limits and +9 cap.
- Recipient policies: per-mailbox action thresholds managed by admin UI/API,
  atomic persistence and explicit global policy on multi-recipient messages.
- Security: admin-only policy mutations/CSRF, non-admin configuration redaction,
  no product renaming, feature flags off by default; old data schema accepted.
- Test suite: unit/integration, tamper regressions, race detector, go vet,
  JavaScript syntax, native Linux/Windows cross-build, and offline HTTP smoke.

## **Hard blockers before calling this 1.0.0**

1. **Independent ARC interoperability** against external RFC and actual relay
   fixtures, multiple chain instances, key rotation, and trusted-forwarder policy.
   ARC sealing and outgoing identity are not provided.
2. **Real Postfix/Dovecot end-to-end action certification**: valid/failing DKIM,
   multi-recipient cases, Junk Sieve routing, hold queue, reject, tempfail and
   delivery confirmation. Must capture queue IDs and mailbox outcomes.
3. **Detection calibration and safe MIME coverage**: representative clean/spam
   corpora, body/attachment false-positive rates, nested archive and macros,
   file extraction and optional ICAP/AV vendor connectors.
4. **Threat-intelligence operations**: managed provider onboarding, feed
   refresh/signature verification, license checks, caching/error budgets,
   provider health, and a real remote fuzzy operator if enabled.
5. **Reliability/release assurance**: patched Go toolchain, repeatable signed
   binaries, CI provenance, Windows Defender QA, crash/upgrade/rollback and
   long-run Postfix throughput qualification on a real test host.
6. **Policy depth**: composite rules and safe per-recipient MTA transaction
   splitting (or explicit global fallback), trained-model drift/rollback and
   audited human review lifecycle.

Do not advertise this binary as a complete Rspamd replacement or production
safe. Keep real mail on a proven filtering path until the tests above pass.

---

# SpamGate v1.0 release gate (2026-10-27)

SpamGate's target is a credible native-first mail/spam control center, **not**
feature-label parity with Rspamd. A passing Go test suite alone is not
production qualification. Current engineering build: **0.6.0-alpha.1** (Go 1.23.2 development artifacts, not production cleared).

## Improvements delivered in the 0.5.0-alpha.1 engineering pass

| Area | Concrete implementation / verification |
|---|---|
| DKIM signature correctness | RFC 6376 final DKIM-Signature header is hashed *without* CRLF. Independent RSA fixture with folded signatures fails on the previous implementation and passes now. Existing Ed25519 tests updated to match the RFC. |
| DKIM failure amplification | A message with many bad DKIM signatures gets a single bounded bad-signature penalty, not +2 per signature; detailed signature evidence remains recorded. |
| DMARC | Organizational-domain policy fallback and relaxed alignment now use a Public Suffix List (including private hosted suffixes). Inherited `sp` policy is evaluated. Transient SPF/DKIM/DNS failures return `temperror`, not definitive DMARC failure. PSD DMARC remains unsupported. |
| SPF | `a` and `mx` CIDR matches correctly support IPv4/IPv6 prefix lengths; MX host lookups count toward SPF budget. Tested dual-CIDR, failing and invalid examples. |
| Recovery | Offline ZIP backup, complete SHA-256 manifest verification, restore to **new nonexistent directory only**, strict archive-path validation, no symlink traversal, file size/count limits, mode 0600. Tests check roundtrips and tampering. |
| Observability | Actual scanner invocations, connector/action counters, errors and scan-duration histogram added to authenticated `/api/v1/metrics`; no addresses, subjects or tokens included. |

### Operational instructions — offline backup and restore

**Stop the SpamGate executable first.** The offline backup command is not a
live filesystem snapshot and must not race with SpamGate writes.

```bash
/opt/spamgate/spamgate -data /opt/spamgate/data -backup-file /secure/location/spamgate-20261027.zip
/opt/spamgate/spamgate -verify-backup /secure/location/spamgate-20261027.zip
```

To test recovery without overwriting the existing installation:

```bash
/opt/spamgate/spamgate -data /opt/spamgate/restore-test -restore-backup /secure/location/spamgate-20261027.zip
/opt/spamgate/spamgate -data /opt/spamgate/restore-test -listen 127.0.0.1:38479
```

The restored test service uses a *different* data directory and loopback HTTP
port. **Do not enable the Milter environment variables for the recovery test.**
The ZIP contains credentials, message history, and possibly saved raw mail.
Keep it in a protected directory and encrypt it at rest using your approved
backup system. `-restore-backup` refuses any existing destination, even an
empty one; it cannot overwrite `/opt/spamgate/data`.

The shipped public-suffix database is an **August 2024 snapshot** from the
MPL 2.0 licensed publicsuffix.org list as distributed in IO::Socket::SSL's
`PublicSuffix.pm`. Because the list changes, provide a recent upstream copy
of `https://publicsuffix.org/list/public_suffix_list.dat` through
`SPAMGATE_PUBLIC_SUFFIX_FILE=/path/to/current/public_suffix_list.dat` and
restart SpamGate when deploying. No outside download is performed by default.

## Hard blockers before a legitimate v1.0.0 release

1. **Real Postfix Milter qualification:** run folded DKIM fixtures, valid/invalid
   SPF and DMARC, multiple recipients, hold, header/tag, deferral and reject
   against an actual Postfix/Dovecot test environment. Correlate Postfix queue
   ID, SpamGate scan ID and end-user mailbox result, including failures.
2. **Independent authentication conformance:** prove results against external
   RFC fixture corpora and independently implemented DKIM/SPF/DMARC verifiers,
   including DMARC PSD, indirect flows/forwarding and ARC cryptography.
3. **Detection depth:** robust MIME/archives/attachments, phishing brand and
   redirection analysis, fresh external DNS feeds under proper usage licenses,
   optional network fuzzy infrastructure and automated accuracy monitoring.
4. **Scoring calibration and safety:** independent clean/spam corpora, false
   positive/negative measurements, regression thresholds, domain/tenant
   policies and alerting. Keep new aggressive modules opt-in until qualified.
5. **Enforcement:** verified MTA disposition, confirmed queue holds/releases,
   safe Junk/Sieve routing, Exim/hosting-panel parity, distinct per-recipient
   delivery policy, operator audit log with review provenance.
6. **Operations:** upgrade compatibility fixtures, crash/restart tests, corrupt
   data recovery, long-run performance, overload and bounded network dependency
   behavior, backups tested end to end on real installed instances.
7. **Release assurance:** supported patched Go compiler, repeatable CI/build,
   provenance and checksums, real Windows runtime QA/Defender checks/signing,
   and staged rollout/rollback. The local Go 1.23.2 compiler remains unsuitable
   for a cleared security appliance release.

Do not rename an alpha binary `1.0.0` to claim these gates passed.
