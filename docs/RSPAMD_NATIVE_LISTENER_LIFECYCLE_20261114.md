# Native HTTP worker lifecycle and scan error boundary — 2026-11-14

The Rspamd-compatible worker remains a native foreground-managed HTTP listener, separate from the administrative console and Postfix Milter listeners. This change does not touch the running mail server, its Postfix configuration, the persistent data directory, or ports 38470/38472.

## Changes

- A canceled context is rejected before opening a socket.
- The shutdown watcher terminates when `Serve` returns, including startup failures, rather than waiting indefinitely for a context that may never be canceled.
- A context cancellation invokes bounded HTTP graceful shutdown; an expected `http.ErrServerClosed` is treated as a clean return.
- Scanner error details are no longer reflected into unauthenticated-to-the-message HTTP responses; callers receive a generic scan failure. Existing status 422 is preserved. Detailed server-side diagnostic logging remains a separate gate.

## Regression coverage

`TestRspamdListenPreCanceledContextDoesNotBind`, `TestRspamdListenOccupiedPortReturnsPromptly`, and `TestRspamdListenStopsOnContextCancellation` cover lifecycle behavior. These tests use ephemeral loopback sockets and never modify a mail host.

## Qualification limits

The native listener tests alone do not prove real Postfix/Dovecot disposition, durable mail acceptance, tenant isolation, classifier precision, UI acceptance, backup/restore, or native rollback. Full Go tests, race tests, CI, and mail-host acceptance must be checked at the final commit. No beta-ready claim is warranted without these gates.
