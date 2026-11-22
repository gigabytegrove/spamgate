# SMTP distinct-recipient admission correction — 2026-11-22

## Production gate
Issues #1/#2/#3: SMTP transaction semantics and duplicate-delivery prevention.

The prior ingress path rejected *all* RCPT TO commands once 100 distinct recipients had been accepted, including an exact repeat of a previously accepted address. That contradicted the duplicate-idempotency contract and could cause a client to treat a valid repeated RCPT as a transient failure.

The ingress now calls `acceptSMTPRecipient(recipients, address, 100)`. Exact repeats receive 250 without consuming a slot; new addresses beyond 100 receive 452 and do not mutate the envelope. Exact local-part case and plus-addressing remain distinct; the helper never rewrites addresses. Legacy outbound envelope deduplication remains unchanged.

## Regression coverage
`internal/transport/smtp_recipient_capacity_test.go` checks all 100 admissions, a repeated first address at capacity, rejection of a 101st distinct address, preservation of envelope order and contents, case-sensitive local parts, plus-addressing, and zero-capacity rejection.

## Evidence and limitations
Source changes and test definitions were published through GitHub. Test execution and final-HEAD CI have not been verified. GitHub commit combined-status lookup returned no statuses, and the available workflow lookup only covers pull-request-triggered runs. No real mail host was accessed. This does **not** qualify Postfix/Dovecot disposition, durable delivery, SMTP interoperability, false positives, tenant policy, browser workflows, backup/restore, or native update/rollback. The 2026-10-31 beta deadline is past; no beta-ready claim is made.

The native launcher, worker, persistent data path, and Milter ports remain untouched. No Docker substitution or live mail-server changes.
