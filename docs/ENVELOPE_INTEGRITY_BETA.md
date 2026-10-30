# SMTP envelope integrity beta gate (2026-10-30)

## Correctness defect

Before this change, an SMTP MAIL FROM:<> transaction could be scanned with
an empty reverse path and then have Message.Sender replaced with the
untrusted RFC 5322 From header. The durable queue used Message.Sender
for its upstream SMTP envelope, potentially changing a delivery status
notification into an ordinary message and enabling bounce loops.

Separately, the delivery worker previously read the sender and recipient
envelope from the mutable history mirror instead of enforcing the immutable,
SHA-256-checked, fsync-backed queue record. A stale or corrupted mirror could
redirect a previously accepted message.

## Implemented

- Preserve null reverse paths for SMTP and Milter scans; unconnected manual
  scans retain the historical From display fallback.
- Treat the durable spool sender and recipients as authoritative during worker
  relay. On history disagreement, reconstruct the scan from the original
  spooled evidence and journal an explicit QUEUE_ENVELOPE_RESTORED finding
  before delivery.
- Refuse delivery if the repair audit cannot be durably persisted. Keep the
  original spool for retry/recovery.
- Add regression coverage for SMTP TCP framing and queue handoff, corrupt
  history restoration, journal failure, and both SMTP and Milter null senders.
- Run the disposable real Postfix/Dovecot CI lab when mail-core or transport
  source changes, rather than only when the lab test file itself changes.

## Verification limits

Go unit/race/vet, isolated Postfix/Dovecot lab and native builds must be
verified from the GitHub Actions runs for the exact commit. The simulated
SMTP server and queue worker do not prove live production-host mail routing,
Dovecot Junk placement, Postfix queue hold authorization, or bounce behavior
across a real upstream relay. No running mail host is reconfigured.

Legacy spool records created by older builds may already contain a rewritten
null reverse path. Their historical envelope cannot be inferred reliably from
the RFC 5322 From header. Do not rewrite legacy records automatically.

## Qualification still required

Issues #1-#9 remain open. Run real null-sender DSN forwarding, Postfix
accept/reject/hold/tempfail, Sieve INBOX/Junk, multi-recipient, DNS
authentication interoperability, classifier corpus metrics, restore and
rollback on disposable and then supervised production-like hosts before
declaring the long-term beta qualified.
