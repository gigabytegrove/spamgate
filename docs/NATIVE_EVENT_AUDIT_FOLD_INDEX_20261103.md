# Event audit Unicode-fold key validation — 2026-11-03

## Change
The native read-only event auditor now indexes object keys by their Unicode simple-fold equivalence class. The previous pairwise EqualFold scan was quadratic in the number of keys of a single JSON object, allowing an attacker-controlled event line to consume disproportionate CPU. Canonicalization uses unicode.SimpleFold and the minimum rune of each cycle, preserving EqualFold semantics without lossy lowercasing. Applies to both root and nested objects.

The regression suite also corrects a double-escaped Unicode fixture so that it actually tests a JSON Unicode escape, and adds a 2,000-key adversarial object.

## Verification boundaries
This parser validates syntax and ambiguity; it does not authenticate event provenance, correlate Postfix queue IDs, or establish that a HOLD actually occurred. The existing 2 MiB scanner cap and 64-level nesting cap remain. No mail host or service is modified. Native launcher, worker, data directory and Milter ports remain unchanged.

## Test
`go test ./cmd/spamgate-event-audit -count=1`
