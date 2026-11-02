# Native operator retry audit and replay safety — 2026-11-02

## Scope and architecture

Issue #2 (durable delivery) and issue #6 (operator diagnostics). This is an additive native Linux safety change, not a new mail path. The permanent foreground launcher remains `/opt/spamgate/spamgate`, the worker remains `spamgate-worker`, the data root remains `/opt/spamgate/data`, and Milter ports remain 38470/38472. No Postfix/Dovecot configuration is modified.

## Durable sequence

1. Authenticate the administrator and require the existing mutating-route CSRF check.
2. Validate the authenticated actor identity and exact queue ID.
3. Acquire the existing cross-process worker lease and queue mutex.
4. Refuse delivered, in-flight, discard-pending, or historically discard-requested originals.
5. Load the immutable accepted original, restore any stale history envelope, and fsync `QUEUE_RETRY_REQUESTED` to the history journal with `manual/<actor>` attribution.
6. Only after a successful journal write, reset retry attempts and schedule using the existing fsync-backed spool publisher.

An unavailable history journal prevents the retry and preserves the accepted original byte-for-byte. If the queue reschedule fails after the journal commit, the HTTP request fails and the audit remains available for reconciliation. The old programmatic `Retry` method routes through the audited path with an explicitly unattributed `legacy API (unattributed)` actor; browser requests use the actual authenticated identity.

## Limits and required qualification

This change does **not** make SMTP delivery exactly once. An interrupted upstream DATA acknowledgment may already represent accepted mail. A manual retry can duplicate it. Production ISPConfig/Postfix/Dovecot testing, crash/power-loss injection, disk-full recovery, operator confirmation UX, complete tenant authorization, and all cumulative issues #1–#9 remain open. Do not interpret green CI as live production qualification.
