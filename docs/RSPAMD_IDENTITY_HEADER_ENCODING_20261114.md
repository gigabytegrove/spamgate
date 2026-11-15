# Rspamd identity-header encoding boundary — 2026-11-14

## Change
The native HTTP compatibility worker now validates UTF-8 and C1 control characters in identity and recipient headers before parsing, scanning, or persisting history. Identity fields are matched case-insensitively across every key in the Go Header map rather than relying on canonical-key lookup, rejecting duplicate noncanonical variants. This prevents a middleware-constructed request from silently selecting one of two conflicting identities. Limits remain 512 bytes for sender and recipient, 255 for HELO, 64 for IP and encodings, and 256 for flags.

## Regression coverage
`rspamd_header_encoding_test.go` adds table-driven cases for valid UTF-8, maximum lengths, truncated/invalid UTF-8, C0/DEL/C1 controls, noncanonical duplicate headers, malformed recipient encoding, and invalid identity encoding. The existing request metadata tests remain in place.

## Evidence and limitations
Starting repository HEAD: `ec488178b032397e5c82ee45f78b8833873bd8de`.
Implementation commit: `943c0b2db18585ad9b46ac14ad2147e311001400`.
Regression commit: `adffbeac89128b876d7b7dac77c4276d8e77df02`.
Local checkout/test execution blocked: `git ls-remote` could not resolve github.com. These tests are committed, not claimed executed. Exact-HEAD CI and isolated Postfix/Dovecot lab must be checked separately; no production host was changed.

## Remaining gates
GitHub issues #1–#9 remain open. This is a narrow protocol integrity improvement, not proof of SMTP authentication conformance, accepted-mail durability, real Postfix holds, tenant isolation, classifier precision, browser acceptance, disaster recovery, or native update/rollback. Do not claim beta qualification without actual mail-host evidence and successful regression gates.
