# SMTP EHLO extension token hardening — 2026-11-19

## Scope
Read-only SMTP diagnostics, issues #3 and #6. No SMTP transaction, credentials, or mail-host configuration changes.

## Change
The supported parameterless EHLO extension parser now requires a nonempty ASCII alphanumeric/hyphen keyword after its existing whitespace and cardinality checks. This rejects control bytes and Unicode lookalikes as valid extension evidence. It does not claim that a server supports an extension merely because it advertises the token.

## Regression
`internal/smtpprobe/extension_ascii_test.go` checks accepted ASCII keywords, rejected control and Unicode bytes, and that malformed supported extensions cannot be trusted without warnings.

## Qualification
Repository test execution must be confirmed by CI. Local checkout unavailable in this environment due to github.com DNS resolution failure. No real Postfix/Dovecot host qualification was attempted. This is not beta acceptance.

## Remaining production gates
Issues #1–#9 remain cumulatively open until independently verified: disposition/holds, durable delivery, SMTP/authentication compliance, classifier accuracy/false positives, tenant policy, diagnostics, complete browser UI, backup/restore and native update/rollback. Preserve /opt/spamgate/spamgate foreground launcher, spamgate-worker, /opt/spamgate/data and Milter ports 38470/38472. No Docker replacement or automatic running mail server changes.
