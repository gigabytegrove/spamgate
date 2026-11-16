# Mail queue error confidentiality — 2026-11-16

The native server now returns fixed, action-specific failure text when a durable delivery retry or discard fails. The full error remains in the server log with the queue item ID and authenticated actor for investigation. This prevents filesystem paths, queue internals, and backend audit details from being sent to browsers.

Postfix HOLD release lock acquisition also returns a fixed 503 message instead of appending the raw lock error. The lock failure and queue ID are logged on the server; the release command is not executed if the lock cannot be acquired.

Changes are restricted to HTTP error handling; queue persistence, delivery semantics, privilege mediation, the foreground launcher, the worker, and Postfix/Dovecot configuration remain unchanged.

Regression coverage: `internal/server/delivery_queue_error_safety_test.go`. Existing `mail_queue_cache_safety_test.go` continues to cover no-store headers. Additional acceptance still required: authenticated endpoint fault injection, production-host Postfix HOLD release, durable delivery replay, real Dovecot mailbox placement, and exact-final-HEAD CI. No production host was modified.
