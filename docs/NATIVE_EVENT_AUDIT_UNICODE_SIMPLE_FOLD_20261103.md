# Audit JSON Unicode case-fold integrity — 2026-11-03

## Scope
The native read-only `spamgate-event-audit` utility must not count ambiguous evidence. Go's `encoding/json` struct-field matching uses Unicode case-insensitive matching, while the earlier duplicate-key validator normalized keys with `strings.ToLower`. These are not equivalent: for example, the Kelvin sign (K) and ASCII K compare equal under `strings.EqualFold` but lowercasing the strings does not necessarily produce identical keys. An attacker-controlled event can therefore contain fields whose interpretation is ambiguous across decoders.

## Change
The recursive decoder compares each new key against previously observed keys using `strings.EqualFold`, at top level and inside objects nested within arrays and objects. It rejects collisions before unmarshalling. The existing 64-level nesting limit, invalid UTF-8 rejection, and malformed-record accounting remain in place.

## Regression contract
`go test ./cmd/spamgate-event-audit -count=1` must pass. Cases cover ASCII collisions, Unicode Kelvin-sign collisions, JSON Unicode-escaped aliases, long-s aliases, and a distinct-key control. The auditor must increment malformed evidence counts and exclude rejected records from Milter disposition totals.

## Verification limits
Source changes were committed through GitHub. This execution environment could not resolve github.com for a full local checkout; no local package tests or real mail-host qualification are claimed. Check exact-final-commit CI and independent Postfix evidence before advancing beta gates. This is evidence validation only, not proof that Postfix actually held, rejected, or delivered mail.

## Architecture
No changes to the permanent native launcher `/opt/spamgate/spamgate`, `spamgate-worker`, `/opt/spamgate/data`, or Milter ports 38470/38472. No production Postfix or Dovecot configuration changes.
