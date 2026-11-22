# Exact SMTP recipient deduplication — 2026-11-22

## Production gate
Issues #1 and #2: duplicate final mailbox deliveries and deterministic durable replay.

## Change
The trusted native SMTP listener acknowledges repeated identical RCPT TO commands with 250, but persists each exact mailbox only once. The outbound relay also deduplicates exact recipient strings in older spool envelopes before issuing downstream RCPT TO commands. Distinct recipients retain their first-seen order. Local parts remain case-sensitive and plus-addresses remain distinct; no mailbox rewriting or speculative canonicalization is performed.

## Verification contract
- Unit test: repeated exact recipients collapse; case-distinct local parts and tagged mailboxes remain distinct; original input remains unmodified.
- Loopback SMTP test: a legacy envelope with duplicate RCPT entries produces one downstream RCPT per exact mailbox, then completes DATA.
- Requires full repository Go tests, race tests, vet, native build, CI and real Postfix/Dovecot mailbox-count verification before claiming delivery qualification.

## Remaining limitations
This prevents one duplicate-delivery cause but does not establish exactly-once delivery. A connection failure after downstream DATA acceptance but before the response remains an ambiguous delivery outcome and may cause an at-least-once retry. SMTP local-part case differences can resolve to the same mailbox on some hosts; collapsing them would require verified destination-specific mailbox canonicalization. No live mail host, ISPConfig configuration, Postfix service, Dovecot service, or running Milter was modified. The launcher /opt/spamgate/spamgate, worker spamgate-worker, data directory /opt/spamgate/data and ports 38470/38472 remain unchanged.

## Outstanding acceptance
Issues #1–#9 remain open. Real hold/release, fsync/crash injection, SMTP/auth conformance, classifier false-positive corpus, tenant policy conflicts, diagnostics, browser workflows, and native backup/update/rollback still require independent qualification. The October 31 beta target is past; no beta-ready claim is warranted.
