# SpamGate long-term beta: mail integrity / transport acceptance gate

## P0: At-least-once is not exactly-once

SpamGate's native SMTP content-filter outbox explicitly implements **at-least-once delivery**, never exactly-once. A message can be accepted by the upstream relay and the local process can crash before recording that remote SMTP 250. After restart a replay can cause a duplicate. This is an unavoidable ambiguity without an idempotent, cooperative destination protocol or an external durable transaction coordinator. **Do not claim zero duplicates.** Admin operators must be shown the attempt count and retained original on failure.

For the Postfix Milter deployment, **Postfix owns SMTP acceptance and queuing**. A SpamGate Milter `continue`, reject, temporary failure, or quarantine callback is a requested action, not independent proof of final mailbox delivery. Validate logs plus queue/mailbox inventory before enabling hard reject on customer domains.

## Changes qualifying in this pass

1. A durable queue now journals the scan decision and original RFC 5322 bytes in one synced outbox record **before sending SMTP 250**. The best-effort `events.jsonl` mirror may fail or a crash may interrupt it; recovery reconstructs history before relaying and does not delete the outbox if history persistence fails. Legacy queue jobs without scan snapshots retain their envelope and receive a conspicuous evidence-limitation finding.
2. Scanning rejects forged/symlinked or invalid outbox objects instead of following arbitrary paths; existing queue capacity/retry/dead-letter limits remain in effect.
3. While a SpamGate worker is active, missing or externally truncated history is not silently re-created by a new scan append. Scheduled compaction first checks the saved journal against the loaded retained scans and refuses to replace a corrupt or inconsistent journal. After successful compaction, Linux fsyncs the directory as well as file data.
4. The Linux single-writer worker lock remains enabled and the native layout stays exactly `./spamgate` (launcher) -> `./spamgate-worker` (application).

## Automated evidence

- SMTP loopback session test sends RFC 5321 envelope/DATA to the actual filtering handler and verifies durable acknowledgement before relay.
- Crash recovery after durable SMTP acceptance but before scan-history append, including preservation of score/action/findings.
- Legacy queue recovery retains missing-history warning rather than claiming original classification.
- Corrupt/symlinked spool refusal.
- Forced disk history write failure preserves the durable original; recovery retries only after storage repair.
- Scheduled history compaction refuses damaged journals without overwriting evidence; append refuses missing or truncated history.
- No automatic release before full Go unit, race, vet, Node regressions, native migration and upgrade tests.

## Required real mail-host beta evidence — NOT covered by GitHub Actions

Perform only on a **designated test mailbox** under an administrator's supervision, not all customer mailboxes:

1. Record existing Postfix `postconf -n` Milter settings, `postqueue -p`, actual Dovecot mailbox/Junk routing, and the current SpamGate worker version; preserve read-only backups.
2. Verify a **legitimate authenticated** external test message reaches the intended mailbox with no false positive and an exact queue ID.
3. Test GTUBE/SGTUBE only against the explicitly allowlisted test mailbox. Observe real Postfix `status=` and SpamGate finding. Compare accept, header tagging, quarantine/hold, and reject behavior. Never call requested actions 'confirmed' until Postfix evidence agrees.
4. Exercise failure behavior with test-only traffic (unavailable scanner, invalid spool, blocked downstream relay) and confirm SMTP 451/tempfail instead of silent 250 on non-durable paths.
5. Check in-place worker update under the permanent launcher, sessions/history preservation, parent survival, reboot/restart, and rollback after intentionally failed test worker. Avoid changing production Postfix routing in a disaster drill.
6. Exercise offline backup `./spamgate-worker -data /opt/spamgate/data -backup-file ...` **while worker is stopped**, and restore only to a fresh test directory with the same worker command. Avoid running `-backup-file` on the supervisor.
7. Capture test case, UTC timestamp, queue ID, Postfix log evidence, SpamGate scan ID, disposition, mailbox receipt and observed outcome in a release acceptance report.

**Beta decision:** GitHub CI passing is development qualification. Long-term beta should begin with **supervised, rollback-capable pilot traffic**, not sole production enforcement, until the above real-host outcomes are recorded and reviewed. False-positive corpus certification, ARC interoperability, full SMTP semantics, customer-domain production scale, and all major #1–#9 issues cannot be asserted from unit tests alone.

## Further durability hardening (October 30 engineering)

- New spool records carry SHA-256 over the immutable scan ID, envelope sender,
  ordered recipients and exact RFC 5322 original. Startup, snapshots and
  delivery reject modified records before forwarding. Existing pre-digest jobs
  remain readable for upgrade compatibility; **the digest is a corruption
  detector, not a keyed signature against a malicious privileged operator**.
- Queue intake and internal persistence reject noncanonical IDs rather than
  allowing IDs to become filesystem paths. The spool directory must be real
  and not group/world writable.
- Admin discard now fsyncs a `discard_requested` history event before deleting
  an original, then records `discarded`. If the history journal cannot be
  written, deletion is refused. If final audit fails after deletion, the
  initial request event remains for forensic reconciliation.
- Offline backup publication uses same-filesystem hard-link creation to
  refuse destination replacement even if another process creates the target
  after the initial check. The parent directory is synced on Unix.
- These controls do not establish final mailbox delivery, prevent upstream
  SMTP 250/crash duplicate ambiguity, or substitute for actual Postfix and
  Dovecot host qualification.

- The immutable spool digest also covers the full saved scan verdict and findings;
  a changed classification cannot silently be replayed as original evidence.
- A cold backup/restore regression now exercises the full original-message
  recovery path: archived outbox, restored data directory, rebuilt scan history,
  one relay attempt and queue finalization.
