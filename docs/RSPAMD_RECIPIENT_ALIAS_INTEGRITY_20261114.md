# Recipient header alias integrity — 2026-11-14

## Root cause and correction

The Rspamd-compatible HTTP worker previously read recipient identities using `http.Header.Values("Rcpt")`. That method looks up the canonical map key and does not enumerate noncanonical keys inserted directly into the header map by middleware or tests. A request containing `Rcpt` and `rcpt` entries could therefore scan only one subset of intended recipients. This creates a recipient-policy coverage gap.

The worker now walks the header map and collects every key matching `Rcpt` using case-insensitive comparison. It enforces the combined 100-recipient limit before allocating more entries, then validates and normalizes every recipient through the existing mailbox parser. The single-value identity headers retain their existing strict duplicate rejection.

## Regression coverage

`internal/transport/rspamd_rcpt_casefold_test.go` tests all three key spellings together, malformed aliases (including invalid UTF-8 and NUL), combined 100/101 recipient limits, and empty aliases.

## Qualification boundaries

This is a request metadata and recipient-policy correctness fix, not evidence of real Postfix/Dovecot delivery or hold semantics. Confirm exact-HEAD Go tests and isolated lab workflow, then qualify with production-host evidence before claiming beta readiness. Issues #1–#9 remain open. No mail-host configuration or runtime architecture was changed.
