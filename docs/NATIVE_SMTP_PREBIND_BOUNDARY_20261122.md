# Native SMTP pre-bind security boundary — 2026-11-22

## Scope and immutable architecture

This change is limited to the native SMTP content-filter listener. It does not change the permanent foreground launcher at `/opt/spamgate/spamgate`, `spamgate-worker`, persistent `/opt/spamgate/data`, or Postfix Milter ports 38470/38472. It does not modify Postfix, Dovecot, live mail, or release artifacts.

## Changes

- Reject nonnumeric, zero, out-of-range, malformed, or zone-qualified listener ports before any socket bind. Explicit wildcard and IPv6 binds remain permitted only with configured trusted CIDRs.
- Revalidate programmatically supplied `net.IPNet` values, including nil values, malformed/noncontiguous masks, mismatched address families and host bits. Environment parsing already validated CIDRs, but manually constructed listeners bypassed that parsing.
- Reject Unicode lookalikes in manually supplied recipient-domain allowlists before ASCII case comparison.
- Use the default structured logger if a listener is constructed without an explicit logger.
- Add focused boundary regression tests for IPv4, IPv6, malformed masks, listener addresses and domain character handling.

## Evidence and outstanding gates

Source-control commits are evidence of source publication, **not** evidence of compilation, functional acceptance or native-host qualification. The local checkout cannot resolve github.com; the available local Go toolchain is below the repository's declared requirement. No owner-controlled builder or mail host was accessed. Therefore compilation, complete tests, end-to-end Postfix/Dovecot evidence, crash recovery, false-positive corpus evaluation, browser acceptance, backup/restore and native rollback are **NOT EXECUTED**. All production issues #1–#9 remain open.

The new tests must be executed from an immutable main SHA on the owner-controlled builder, with full logs, source provenance and SHA-256 recorded. Do not treat GitHub Actions or commit statuses as qualification. Do not deploy or change the running mail server without explicit owner authorization and existing acceptance gates.

## Residual risk

Pre-bind validation does not establish durable delivery, exact recipient disposition or mailbox placement. It does not prove the scanner/store or queue is healthy after startup, nor that a remote relay will accept mail. Actual end-to-end evidence and failure injection are still required. The October 31, 2026 target has passed; beta remains unqualified.
