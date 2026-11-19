# Mapped-address phishing classifier regression — 2026-11-19

Issue #5: A public-IP phishing destination heuristic previously evaluated an IPv4-mapped IPv6 literal without normalizing it to its underlying IPv4 address. This could misclassify mapped private, loopback, or link-local addresses as public. The implementation now calls netip.Addr.Unmap(), rejects scoped literals, and retains explicit private, loopback, link-local, and multicast exclusions. Public IPv4-mapped addresses remain eligible for deceptive visible-link mismatch checks.

Regression coverage adds mapped private/loopback/link-local/public addresses, scoped IPv6, multicast, and unspecified addresses to the destination-host predicate tests. This is an incremental classifier correction, not an independently measured false-positive rate or production-mail acceptance.

Locked native architecture unchanged: /opt/spamgate/spamgate foreground launcher, spamgate-worker, /opt/spamgate/data, Postfix Milter 38470/38472. No mail-host configuration or runtime process modified.

Verification: GitHub writes and source inspection; repository-wide tests and exact-HEAD CI require independent execution. Remaining acceptance: all issues #1–#9, especially mail disposition, durable delivery, protocol conformance, tenant policy, diagnostics, UI, backup and native rollback.