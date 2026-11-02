# Native Postfix HOLD HTTP authorization and audit safety — 2026-11-01

Scope: production gates #1, #6 and #9. This change strengthens the **administrator HTTP-to-privileged-release boundary**; it does not certify a production mail host.

## Implementation

- The POST /api/v1/messages/{id}/postfix-release body is now limited to 16 KiB and parsed with strict JSON structural validation before the existing exact queue ID, confirmation and reason checks. Duplicate, Unicode-escaped and case-folded aliases, trailing JSON, invalid UTF-8, unknown fields, non-object roots and oversized bodies are rejected before queue inspection or audit mutation.
- Release reasons reject control characters, line separators and excessive length to avoid multiline audit-log injection.
- The privileged helper subprocess has a bounded inherited-pipe wait; failed command stderr is no longer echoed to the HTTP client. A successful response no longer returns raw helper stdout/stderr. Server-side diagnostics and the durable attempted/submitted audit states remain.
- HTTP regressions cover unauthenticated and mailbox requests, CSRF/origin denial, malformed request bodies, exact complete multi-recipient correlation, success, persistent audit, duplicate prevention, and failed-command privacy and no-blind-retry semantics.

## Qualification boundary

The new HTTP tests use an injected Postfix inventory and command and therefore **do not** prove real helper execution, actual Postfix queue release or final Dovecot mailbox receipt. Existing disposable Linux CI separately exercises actual helper privilege and MTA delivery. A combined real HTTP-to-helper integration remains a separate gate until its exact-commit CI evidence is inspected.

Locked native architecture remains unchanged: /opt/spamgate/spamgate foreground launcher, spamgate-worker, persistent /opt/spamgate/data, and Milter 38470/38472. No production Postfix or Dovecot configuration is modified automatically. The October 31 target has passed; this change is not a beta readiness declaration.
