# Native spool JSON Unicode escape integrity — 2026-11-01

## Root cause
Go encoding/json replaces unpaired UTF-16 surrogate escapes with U+FFFD. An on-disk spool JSON string containing an actual U+FFFD can be rewritten using an invalid escape such as backslash-u-d800; the decoded struct, immutable SHA-256 and mutable state SHA-256 remain identical. The prior duplicate-key validator did not reject this lossy representation.

## Contract
Validate now rejects lone high or low surrogates, incorrectly paired surrogates, truncated or invalid hexadecimal escapes, and intervening characters between a surrogate pair. Valid paired escapes, literal UTF-8 and escaped literal backslashes remain accepted. The scanner uses constant auxiliary memory and reports no message contents. It runs before the Go JSON decoder in the shared spooljson validator, protecting queue startup, inventory, delivery, and read-only forensic audit.

## Evidence
Local Go 1.23.2 isolated helper regression tests, race detector, and vet passed. Full repository integration tests and exact-commit CI are required before qualification. The queue and audit regressions reproduce digest-matching malformed input and verify refusal without delivery or modification of the forensic original.

## Limitations
This is an integrity/canonicalization guard, not a keyed MAC or an exactly-once SMTP guarantee. No production mail host, DNS backend, mailbox placement, cold restore, or native updater was exercised. All nine cumulative production gates remain open. The permanent native launcher, worker, data root and Milter ports are unchanged.
