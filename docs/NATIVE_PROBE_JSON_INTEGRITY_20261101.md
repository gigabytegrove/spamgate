# Native host probe JSON integrity — 2026-11-01

## Root cause

The opt-in `--check-services` health probe trusted Python's permissive JSON
defaults: duplicate keys silently overwrote earlier values, NaN/Infinity were
accepted, malformed UTF-8 could escape the error handler, and HTTP
`Content-Type` was not validated. A contradictory response could be reported
as `status=ok`; malformed input could prevent the promised JSON report.

## Fix

- Require JSON media type (`application/json` or `application/health+json`).
- Enforce strict UTF-8, no duplicate object keys at any depth, no non-finite
  JSON constants, no trailing documents, and bounded 4096-byte responses.
- Convert excessive nesting and malformed encodings into structured failure
  reports rather than unhandled exceptions.
- Add deterministic unit and actual loopback HTTP/TCP integration regressions.
- Keep default invocation entirely filesystem-only. Opt-in probes remain
  read-only, do not send SMTP, and never negotiate Milter.
- When `--send` is explicitly requested, a failed service probe continues
  to prevent the SMTP transaction.

## Limits

A healthy JSON response and open TCP port do **not** authenticate the worker,
verify the Milter protocol, prove Postfix acceptance, or establish Dovecot
mailbox delivery. Real mail-host evidence is still required for issues #1/#6.
No running mail server was changed.
