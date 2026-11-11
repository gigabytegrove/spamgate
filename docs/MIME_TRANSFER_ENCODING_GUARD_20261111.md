# MIME attachment transfer-encoding guard — 2026-11-11

## Change

`internal/core/attachment_inspection.go` now permits unencoded MIME bodies only when `Content-Transfer-Encoding` is absent or one of `7bit`, `8bit`, or `binary`. Existing `base64` and `quoted-printable` bounded decoding remains in place. Unsupported encodings return a decode error instead of treating the encoded bytes as the decoded attachment. In the active MIME inspection path this produces `MIME_UNREADABLE` diagnostic evidence (zero score); forwarded `message/rfc822` wrappers also produce `MIME_UNREADABLE` when decoding cannot be performed safely.

## Regression coverage

`internal/core/attachment_transfer_encoding_test.go` covers allowed unencoded transfer types, case-insensitive base64, quoted-printable, unknown encoding, malformed base64, and a complete multipart message whose unknown encoding must produce `MIME_UNREADABLE` without falsely scanning its raw `MZ` prefix as decoded executable content.

## Qualification boundaries

This is diagnostic visibility, not a disposition or quarantine policy. Unknown encodings are not decoded, and this change does not guarantee that a message is held, rejected, or quarantined. Native launcher, worker, persistent data and Milter port contracts remain unchanged. The test source was committed, but the exact commit was not locally executed because GitHub DNS resolution blocked checkout. GitHub's commit-workflow lookup currently exposes only pull-request runs, so an empty result cannot certify push CI. A real Postfix/Dovecot host has not been qualified. Issues #1–#9 remain production gates.
