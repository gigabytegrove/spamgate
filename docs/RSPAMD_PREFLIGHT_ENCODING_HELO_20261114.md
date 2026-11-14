# Rspamd-compatible HTTP preflight: encoding and HELO integrity

## Scope
The native HTTP worker previously rejected only compressed requests containing a nonempty Compression header or a Content-Encoding containing the substring `zstd`. Other encodings such as gzip, br, or chained encodings could be passed as opaque bytes to the MIME scanner. The worker also trimmed HELO whitespace rather than validating the supplied identity before SPF evaluation.

The request preflight now rejects all nonempty Compression headers and every Content-Encoding except absent or identity, and validates HELO using the existing SMTP XFORWARD identity validator. Supported unavailable HELO markers map to an absent HELO identity. The check runs before reading the request body or invoking the scanner.

## Compatibility
Uncompressed RFC 5322 requests with absent or identity Content-Encoding remain accepted. Requests relying on compressed body decoding are rejected with HTTP 415 until explicit bounded decompression is implemented. Invalid HELO is rejected with HTTP 400 rather than silently normalized. This is a deliberate compatibility change; validate actual Postfix/Rspamd client configurations before deployment.

## Qualification
Unit tests cover representative valid and malformed HELO identities and compressed or chained encodings. Full-repository CI and a real Postfix/Dovecot mail-host acceptance test must be independently observed at the exact final commit. No production mail server was modified. This does not close issues #1–#9 or establish long-term beta readiness.
