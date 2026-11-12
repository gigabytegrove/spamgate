# SMTP SIZE separator ambiguity evidence — 2026-11-12

## Change
The read-only SMTP diagnostic recognizes malformed SIZE extension tokens using separators `:`, `;`, `,`, `/`, `+` and `-` in addition to the previously recognized equals form. Such tokens produce `MALFORMED_SIZE_ADVERTISEMENT`. When another SIZE declaration exists, `DUPLICATE_SIZE_ADVERTISEMENT` takes precedence and no numeric size limit is trusted, regardless of ordering. The EHLO identity line is excluded; unrelated extensions such as SIZEX are not treated as SIZE.

## Coverage
`internal/smtpprobe/size_separator_ambiguity_test.go` adds twelve duplicate-order cases, five malformed-single cases, and identity/unrelated-keyword cases. These are source-level regression tests; successful execution must be established independently.

## Qualification boundary
No SMTP AUTH, MAIL FROM, RCPT TO or DATA is sent by this change. No running mail host or native service configuration is altered. The locked launcher, worker, data directory and Milter ports remain unchanged. This parser fix is not proof of mail delivery, classifier precision, tenant enforcement, backup integrity or host acceptance. Exact-HEAD CI and real-host evidence remain separate production gates.
