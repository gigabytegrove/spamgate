# Special-use IP phishing false-positive boundary — 2026-11-19

## Scope
Issue #5. The visible-link phishing detector already recognized public IP literals as possible deceptive destinations, but Go's global-unicast predicate includes special-use address space. That allowed a visible brand URL linking to documentation, carrier NAT, benchmarking or reserved addresses to be counted as a public-IP phishing mismatch.

## Change
Explicitly exclude 0/8, 100.64/10, 192.0.0/24, the three RFC 5737 TEST-NET blocks, 198.18/15, 240/4 and 2001:db8::/32. IPv4-mapped IPv6 is normalized before checking the prefixes. The detector still scores ordinary public IPv4/IPv6 literals and mismatching public domains. The exclusion is conservative and does not claim to implement the entire evolving IANA special-purpose registry.

## Tests
Added predicate boundary cases and full HTML phishing-path regressions for special-use addresses. Source and test commits were pushed to main. Local full-repository execution is blocked by GitHub DNS resolution and the local Go toolchain being 1.23.2 versus go.mod 1.27.4. No passing repository tests or final-HEAD CI are claimed.

## Production acceptance
This is not corpus-calibrated accuracy evidence, live Postfix/Dovecot evidence or a completed issue. All issues #1–#9 remain open. Native architecture stays unchanged: /opt/spamgate/spamgate foreground launcher, spamgate-worker, /opt/spamgate/data, Milter ports 38470/38472. No running mail host was touched.
