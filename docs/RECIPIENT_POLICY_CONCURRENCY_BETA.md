# Recipient policy concurrency safety — beta

The admin-only GET /api/v1/config returns `recipient_policies_revision`, a SHA-256 digest of the mailbox-sorted policy set. PUT /api/v1/recipient-policies now requires `expected_revision` alongside the complete `policies` array. Missing revision: HTTP 400. Stale revision: HTTP 409, with no write. Comparison and atomic persistence occur under the Store lock.

The browser submits its loaded revision and refreshes on conflict. Existing third-party clients of the complete-set replacement endpoint must supply the revision. Existing stored policies need no migration.

This prevents lost updates but does not certify per-recipient Milter enforcement: multi-recipient SMTP transactions continue to use global thresholds. Live Postfix delivery, cross-tenant conflicts, UI multi-admin browser tests, and full issue #4 acceptance remain open.
