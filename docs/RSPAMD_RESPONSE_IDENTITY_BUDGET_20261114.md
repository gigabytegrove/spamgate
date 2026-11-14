# Rspamd HTTP response identity and aggregate metadata boundary — 2026-11-14

This change is an incremental protocol-integrity hardening pass, **not** a production mail-host acceptance result.

## Behavior

The HTTP scan response is rejected with HTTP 503 before history persistence when the scanner returns an empty, malformed or oversized internal scan correlation ID; a Message-ID containing control bytes, invalid UTF-8 or more than 998 bytes; or more than 1 MiB of aggregate symbol, detail and source metadata. A missing Message-ID remains legal. Scanner-generated IDs are 32-character lowercase hexadecimal strings (core.ID), inside the permitted 128-byte alphanumeric/underscore/hyphen boundary. The existing per-finding limits and 4096-finding limit remain.

The aggregate budget is charged per occurrence, including repeated symbols, preventing repeated 4096-byte options from bypassing a per-field limit. The boundary rejects, rather than silently truncating, evidence. No mail server, Milter configuration, data directory, or native launcher was changed.

## Evidence and limits

Starting main: 3a763dced8ff8853513d8e22f96c9e0f91c1909c. New tests cover 15 response-identity cases and a repeated-symbol aggregate-budget boundary. The identity helper and tests were executed in an isolated Go 1.23.2 module with representative core.Message fields; go test and go vet passed. That is not an exact-repository regression. The symbol-budget tests were committed but not executed locally. GitHub checkout was blocked by github.com DNS resolution. The connector's commit workflow lookup returns only pull-request-triggered workflows; an empty result is not evidence of push CI success or failure. Production Postfix/Dovecot, ISPConfig, durable-delivery failure injection, full UI browser tests, backup/restore, native update/rollback, and classifier accuracy/false-positive gates remain unqualified. Issues #1–#9 must not be closed on this evidence.

## Architecture lock

Keep /opt/spamgate/spamgate as permanent foreground launcher, spamgate-worker as worker, /opt/spamgate/data persistent, native Linux deployment, and Postfix Milter ports 38470/38472. No Docker substitution or automatic running-mail-server modification.
