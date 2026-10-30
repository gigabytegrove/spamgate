# Mixed-recipient custom-rule isolation — October 30, 2026

## Defect

A global `recipient_email` rule previously matched if **any** envelope recipient equalled its configured mailbox. Because the Milter returns one action for an entire SMTP transaction, a targeted mailbox's reject, quarantine, accept or custom score could inadvertently affect unrelated recipients in the same transaction.

## Enforcement

A `recipient_email` rule now applies only if every envelope recipient matches the configured mailbox. Case-insensitive duplicate recipients remain eligible. Mixed transactions skip the recipient-scoped rule, regardless of its score or forced action. A bounded count of skipped rules is recorded in the scanner's custom-rule trace without disclosing recipient addresses.

Global sender, sender-domain and other transaction-wide rules are unaffected. Owner-scoped rules retain their existing all-recipient safety check. This is an explicit safe fallback, **not** automatic Postfix recipient splitting. It does not satisfy issue #4's full tenant lifecycle, per-recipient splitting, staged rollout or policy conflict acceptance.

## Regression gates

`go test ./internal/core -run 'TestRecipientEmailRules|TestGlobalRuleStillApplies' -count=1`

`go test ./... -count=1`

`go test -race ./...`

Verify the exact-commit GitHub engineering and isolated Postfix/Dovecot workflows before reporting qualification. Do not change the production Postfix configuration automatically.
