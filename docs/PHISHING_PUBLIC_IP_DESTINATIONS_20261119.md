# Public-IP phishing destination coverage — 2026-11-19

Issue #5: The browser-visible URL mismatch classifier rejected all destination IP literals through ValidReputationDomain, even when a clickable HTTPS URL pointed to a public IP while its text claimed an unrelated domain. The reputation-domain predicate remains unchanged. A dedicated phishing destination predicate now accepts globally unicast, non-private IP literals for comparison, while excluding loopback, link-local, and private addresses.

Regression fixtures cover public IPv4/IPv6 mismatch, internal and loopback exclusions, benign same-domain links, and existing domain mismatch behavior. This is heuristic evidence only, not an independently measured phishing corpus, false-positive rate, or live-mail qualification. No SMTP disposition, tenant policy, service launcher, Postfix, or Dovecot settings are changed.

Verification: source reviewed; Go tests and final-HEAD CI must be checked separately. Open issues #1–#9 remain acceptance gates.
