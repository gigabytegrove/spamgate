# SpamGate 0.6 external intelligence and detection controls

All new detectors are **opt-in**. They do not override or replace SPF, DKIM,
DMARC, or ClamAV and do not force acceptance or rejection. A positive hit may
contribute at most the documented points. External feed owners are responsible
for lawful use, subscriptions, refresh schedules, and licensing.

## External fuzzy reputation (HTTPS, custom JSON API)

In Protection level, enable **External fuzzy reputation**. Set:

```
SPAMGATE_FUZZY_URL=https://your-approved-provider.example/v1/check
SPAMGATE_FUZZY_TOKEN=<provider-secret>
```

SpamGate sends an HTTPS `POST` with `Authorization: Bearer ...` and JSON:

```
{"algorithm":"spamgate-simhash64-v1","fingerprint":"16-digit-lowercase-hex","shingles":77}
```

The provider must return HTTP 200 and JSON like:

```
{"label":"spam","confidence":0.99,"samples":80,"provider":"example"}
```

Only a `spam` label with confidence >= 0.95 and >= 5 samples adds +2.
All other responses score zero. Total request budget is 800 ms; errors, redirects,
non-HTTPS URLs, malformed responses, and over-4 KiB responses never create a
spam hit. No raw email, sender, recipient, attachment, URL or message ID is sent.
**Privacy warning:** even a SimHash reveals an approximate content fingerprint,
so a third party may correlate or probe content. This is *not compatible* with
Rspamd's fuzzy worker protocol. SpamGate does not ship a public fuzzy server;
connect only an independently operated provider that implements this JSON API.

## Offline curated threat snapshot

In Protection level, enable **Use a dated external threat feed** and set
`SPAMGATE_THREAT_FEED_FILE=/opt/spamgate/feeds/current.json`.

An administrator-controlled updater must write the snapshot atomically. The
file is checked every 30 seconds, limited to 2 MiB and a maximum of 10,000 IPs
and 10,000 domains. Example:

```json
{
  "source":"Owned and licensed threat list",
  "generated_at":"2026-10-27T12:00:00Z",
  "expires_at":"2026-10-28T12:00:00Z",
  "ips":["203.0.113.1"],
  "domains":["bad.example"]
}
```

The addresses above are documentation examples, not real threat indicators.
For real use, only global unicast public IPs may be listed. Indicator domains
must not be public suffixes, names must be lowercase, and dates must indicate
freshness. Expired feeds, invalid entries, oversized files, and missing files
are treated as unavailable; they never create positive results. Only exact IP
matches and hostname/subdomain matches are supported. Positive indicators score
+3 each, capped at +9 per message. This initial version does **not** download
feeds, verify supplier signatures, parse CIDRs, or assess IP-provider licensing.

## MIME and attachment contents

Enable **Inspect attachment contents and archives**. Scans common decoded
MIME parts up to bounded depth/size, checks executable file magic, examines ZIP
member names and declared expansion ratios without decompressing ZIP contents,
and flags encrypted archives as unknown rather than automatically malicious.
The combined additional score is capped at +10. File-based malware detection,
macro parsing, password-cracking, nested archive unpacking, detonation, ICAP
vendor integrations, and real-world false-positive calibration are not
implemented; continue using ClamAV for malware detection.

## Mailbox policies

Protection level contains **Mailbox-specific scoring**. These are overrides of
the tag, quarantine and reject *thresholds*, not independent scanning rules.
The API is `PUT /api/v1/recipient-policies` (admin + CSRF), with body:

```json
{"policies":[{"mailbox":"recipient@example.org","tag_threshold":7,"quarantine_threshold":14,"reject_threshold":24}]}
```

The operation atomically replaces the entire policy list. Up to 200 unique
mailboxes. For a transaction with exactly one recipient, a matching override
is used and saved in the scoring trace. For **multiple recipients**, global
thresholds are used even if a recipient has a custom policy. An MTA must split
multiple-recipient transactions for independent enforcement; SpamGate cannot
claim to enforce different Milter actions for individual recipients in one
SMTP transaction.

## ARC

The ARC diagnostic now verifies the newest ARC-Message-Signature and every
ARC-Seal signature in sequence, with a five-second global DNS budget. It
rejects claimed `cv=pass` when signatures fail, and a signed chain remains
**informational with score zero**. It does not blindly trust forwarders,
override DMARC, or sign outgoing messages. Broad independent interop tests,
trusted-sealer policy, key revocation and ARC sealing still need qualification.
