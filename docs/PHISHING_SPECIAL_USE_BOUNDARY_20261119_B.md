# Special-use phishing destination boundary — 2026-11-19

## Scope
Issue #5, false-positive prevention for visible-link hostname mismatch. The detector now excludes deprecated IPv4 6to4 relay anycast (192.88.99.0/24), IPv6 benchmarking (2001:2::/48), deprecated ORCHID (2001:10::/28) and ORCHIDv2 identifiers (2001:20::/28). The existing 198.18.0.0/15 benchmarking exclusion already includes 198.19.0.0/16 and was not duplicated.

## Security and operational behavior
Only the phishing mismatch destination predicate changes. These special-purpose addresses are not scored as public phishing destinations. This does not authorize or block SMTP delivery, resolve DNS, modify mail hosts, or assert that an address is reachable. Adjacent addresses and a known public IPv6 resolver are regression controls. Full IANA registry conformance and measured ham/spam precision/recall remain unqualified.

## Evidence
Inspected main's existing `internal/core/phishing.go` and `internal/core/phishing_public_ip_test.go`, and GitHub issues #1–#9 before edits. Added predicate boundary tests and full HTML path regressions. Source changes were committed through the GitHub contents API. Local checkout and full Go execution are blocked by unavailable GitHub DNS and a local Go 1.23.2 toolchain against repository Go 1.27.4. No successful repository test or production mail-host result is claimed here. CI results must be inspected on the final HEAD.

## Remaining acceptance
Independent corpus false-positive measurements, current special-purpose registry audit, real Postfix/Dovecot delivery and hold evidence, durable spool fault injection, SMTP authentication conformance, tenant policies, diagnostics, browser workflows, disaster recovery and native update/rollback remain open. The native launcher, worker, persistent data directory and Milter ports are unchanged.
