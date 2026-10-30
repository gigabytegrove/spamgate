# Native MIME text/filename coverage — October 30, 2026

## Engineering scope

The main scanner's bounded MIME text, URL and filename extractor now shares a **75-part budget across the entire nested multipart tree**, not 75 parts per nesting level. It checks for a 76th part, unreadable/malformed multipart boundaries, a 5 MiB individual part limit, an 8-level nesting limit, a 2 MiB decoded-text limit, and a 100-URL extraction limit. Oversized parts are not processed as though the first 5 MiB represented a complete message section.

Any exceeded bound produces a persisted `MIME_COVERAGE_INCOMPLETE` finding with **score 0**, source `diagnostic/mime`, and a scan-trace check with status `error`. The finding contains only bounded, fixed operator explanations; it does not copy message content or recipient addresses. The scanner continues using its existing SMTP disposition. Incomplete parsing is not independent evidence of malicious intent, so it does not automatically reject legitimate mail.

This change affects the built-in text/URL/filename extraction path. Optional MIME attachment-content and ZIP inspection remains separate, with its own limits. This is not a claim that the complete original was inspected or that nested RFC822 bodies and all encoded content are detected. Inspecting beyond these limits safely, and independently labelled false-positive/recall qualification, remain open under issue #5.

## Verification

`go test ./internal/core -run 'TestMIMEExtraction' -count=1`

`go test ./... -count=1`

`go test -race ./...`

The exact-commit GitHub engineering and Postfix/Dovecot workflows must be checked after push. Passing these tests does not qualify the running mail server or establish corpus accuracy.

## Strict transfer encoding

Base64 and quoted-printable text are now decoded with explicit error detection. Invalid base64, invalid quoted-printable and unsupported text transfer encodings produce zero-score `MIME_COVERAGE_INCOMPLETE` evidence instead of silently treating the undecodable source bytes as ordinary readable content. Standard `7bit`, `8bit`, `binary` and absent transfer encodings remain supported. A decoded body exceeding 2 MiB is marked incomplete before truncation. Tests cover valid and invalid encodings, unsupported encoding, URL extraction and the decoded-text boundary.
