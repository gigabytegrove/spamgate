# Native SMTP DATA wire safety and durable dead-letter behavior — 2026-10-30

## Scope
The native Go relay uses RFC 5321 DATA and optional 8BITMIME/SMTPUTF8; it does not implement CHUNKING/BDAT or BINARYMIME. A queued original containing NUL, a bare CR, or a DATA line longer than the RFC 5321 1000-octet limit (including CRLF and dot-stuffing) cannot safely be forwarded. The preflight now refuses the message **before MAIL FROM**, preserving the immutable original in the durable queue. The queue records a `QUEUE_DELIVERY_DEAD` finding after one attempt for deterministically invalid originals; manual recovery remains available.

Unlike deterministic malformed originals, upstream missing SMTPUTF8/8BITMIME, SIZE incompatibility, authentication failures, DNS/TLS errors and temporary 4xx replies are **retryable**. A real SMTP 5xx at MAIL/RCPT/DATA remains permanently rejected as before.

## Compatibility and limits
Legacy LF-only originals remain accepted; Go's SMTP dotWriter canonicalizes LF to CRLF on the wire. Therefore the stored original is immutable, but LF-only originals are **not** byte-identical on the wire. No claim of exact byte-for-byte transport is made. This implementation does not solve ambiguous post-DATA acknowledgements or multi-recipient RCPT policy conflicts.

No Postfix settings, systemd units, live mail hosts, or Milter ports are modified. Production still uses `milter_default_action = accept` and requires separate real-host qualification.

## Regression evidence required
Run `go test -count=1 ./internal/transport`, `go test -race -count=1 ./...`, `go vet ./...`, the browser and native migration suites, native builds, and isolated Postfix/Dovecot integration. Test fixtures cover NUL in header/body, bare CR, 998-octet DATA limits, leading-dot stuffing, UTF-8 byte counting, queue retention, single-attempt dead-letter, and retryable capability mismatch. Passing CI is not proof of actual mail-host qualification.
