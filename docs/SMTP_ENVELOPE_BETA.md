# SMTP envelope conformance and durable listener gate — October 30, 2026

The native SMTP content-filter listener now refuses startup without its
fsync-backed delivery queue. No direct-to-relay mode is exposed by the live
listener. This is distinct from Postfix Milter mode, where Postfix owns the
SMTP queue and SpamGate only requests Milter actions.

RFC 5321 paths must use angle brackets. The listener explicitly accepts
`MAIL FROM:<> ` (null sender), `SIZE=` with bounded decimal parsing, and
`BODY=7BIT` / `BODY=8BITMIME`. A declared SIZE over 10 MiB receives
SMTP 552 before DATA. Unknown ESMTP parameters, malformed paths, duplicate
parameters and unadvertised DSN recipient options are rejected instead of
being silently ignored. A new malformed or oversized MAIL command clears
the previous sender/recipient transaction to prevent stale-envelope reuse.

Scanning now has a 45-second context budget. This is bounded handler behavior,
not independent proof of every DNS resolver or antivirus cancellation path.

Regression tests cover envelope parsing, size rejection, stale transaction
reset, unsupported DSN options, and refusal to listen without the durable
outbox. Real Postfix/Dovecot delivery, SMTP AUTH/STARTTLS interoperability,
DKIM/SPF/DMARC conformance and representative false-positive corpora remain
separate beta qualification gates.
