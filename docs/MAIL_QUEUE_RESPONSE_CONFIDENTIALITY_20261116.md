# Mail queue response confidentiality — 2026-11-16

The Postfix HOLD inventory and durable-delivery queue endpoints now emit `Cache-Control: no-store` before authorization, including denied requests and mutation responses. Shared intermediaries and browsers must not persist queue metadata, sender/recipient identities, administrative decisions, or privileged action outcomes.

The Postfix release path no longer returns the raw inventory-provider error to HTTP clients when a fresh ownership inventory cannot be obtained. The full error is recorded in server logs with the queue ID; the client receives a fixed failure message. This change does not alter Postfix queue state or relax release authorization, and it does not imply downstream delivery.

Scope: `internal/server/postfix_hold.go`, `internal/server/delivery_queue.go`, and `internal/server/mail_queue_cache_safety_test.go`.

Verification required: final-HEAD Go regression tests and isolated Postfix/Dovecot lab; real-host Milter HOLD, release, durable delivery and mailbox placement remain separate acceptance gates. No running mail server is automatically reconfigured.
