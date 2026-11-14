# Native SMTP tenant recipient-domain policy — 2026-11-13

## Scope and production gate
The SMTP listener's `SPAMGATE_ALLOWED_RECIPIENT_DOMAINS` now accepts only explicit, canonical ASCII DNS hostnames, with each label between 1 and 63 octets and the entire domain at most 253 octets. Wildcards, trailing dots, empty labels, address literals, underscores, Unicode lookalikes and malformed labels fail closed at configuration time. Operators must use punycode A-labels for internationalized names. Input case is normalized to lowercase before validation.

Recipient matching remains exact: allowing `example.com` does not allow `sub.example.com`, `notexample.com`, or `example.com.evil`. The native SMTP listener does not change Postfix configuration or start mail services.

## Changes
- `internal/transport/smtp_recipient_domain_policy.go`: strict DNS allowlist parser.
- `internal/transport/smtp.go`: invoke validation during `SMTPFromEnv`.
- `internal/transport/smtp_recipient_domain_policy_test.go`: syntax and recipient-boundary matrix.
- `internal/transport/smtp_recipient_domain_config_test.go`: configuration integration cases.

## Qualification limits
This is tenant recipient-domain configuration hardening, not a claim of complete tenant isolation or Postfix/Dovecot production qualification. Exact-HEAD Go test execution, isolated mail-lab results and host evidence must be checked independently. Durable delivery, actual mail disposition, classifier calibration, browser acceptance, backup/restore, and native update/rollback remain open. The original October 31 beta target has passed.

## Architecture invariants
Keep `/opt/spamgate/spamgate` as foreground launcher, `spamgate-worker`, persistent `/opt/spamgate/data`, and Milter ports 38470/38472. No Docker substitution and no automatic modification of the running mail server.
