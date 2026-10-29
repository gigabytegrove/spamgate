# SpamGate categories and SGTUBE — alpha.15

## Verification paths

1. **Admin laboratory:** Run a harmless category-specific RFC 5322 message through SpamGate's scanner. Each test is in-memory, without mail delivery, persistence, or training. This verifies the marker/scan path, not that the corresponding real-world detector is accurate.
2. **Actual Postfix/Milter:** Opt in only a dedicated test mailbox using the worker environment variable SPAMGATE_TEST_RECIPIENTS=spambox@example.org. Restart with the existing spamgate-run launcher. Download a category .eml sample from the UI and send from an external mail system. Correlate the scanner's SGTUBE finding with actual Postfix Milter and queue logs. Do not send samples to ordinary mailboxes.
3. **Real detection:** Use independently labeled legitimate and spam corpora to measure precision, recall and false positives by category, plus actual end-to-end recipient delivery.

The standard GTUBE signature is supported, but only in admin simulation or for the explicitly configured single test mailbox. Nonmatching and multi-recipient mail are never artificially forced to reject. Other filters may reject the sample before it reaches SpamGate.

## Taxonomy

| Group | Category list |
| --- | --- |
| General | Generic spam |
| Bulk | Unsolicited bulk marketing; unwanted newsletters |
| Fraud | Phishing; credential theft; invoice/payment fraud; cryptocurrency scams; extortion |
| Authentication | Identity spoofing |
| Threats | Malware; ransomware lures; suspicious attachments |
| Content | Adult-content spam; gambling spam |
| Commerce | Counterfeit goods |
| Signals | Reputation-based spam |

Every new scanner result stores the primary category and its evidence-bearing category tags, with synthetic test matches explicitly marked. Unsupported genuine automatic detectors are never presented as working. Older scan history is not silently rewritten.

## Administrator API

- GET /api/v1/spam-categories — taxonomy, unique category test markers, recent counts, test-mode status.
- GET /api/v1/spam-categories/{id}/messages?limit=100 — category history list, bounded to the most recent 1,000 retained scans.
- GET /api/v1/spam-categories/{id}/sample.eml?recipient=spambox%40example.org — harmless generated sample.
- POST /api/v1/spam-categories/{id}/simulate — authenticated, CSRF-protected dry-run with no storage or mail delivery.

Historical counts are a bounded sample, not all-time accounting. A synthetic test verdict is not proof Postfix applied it. The browser exposes copyable markers, sample downloads, category lists and simulation controls.

## Not yet complete

Full real-world classifier coverage in synthetic-only categories, editable category policy/list management, all-history indexed classification, campaigns/clustering, detection corpus qualification, live Postfix delivery outcomes and auto-feedback training. Alpha.14 should remain unchanged until the alpha.15 exact-commit release is qualified.
