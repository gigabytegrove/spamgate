# MIME diagnostic evidence budget and RFC defaults — 2026-11-11

## Implementation

- Missing Content-Type is interpreted as RFC 2045's default `text/plain; charset=us-ascii`, rather than producing a false `MIME_MALFORMED` diagnostic for an otherwise valid message.
- The 20-finding output limit now reserves its final slot for `MIME_FINDINGS_TRUNCATED` if more evidence is encountered. This makes bounded diagnostic output visibly incomplete instead of silently omitting later findings.
- These are diagnostic-only changes. They do not modify SMTP verdicts, quarantine, Postfix/Dovecot configuration, privilege boundaries, or message persistence.

## Qualification evidence

Previous main HEAD inspected: `dece67be739822cbbf3315080411340e1789f005`.
Implementation: `internal/core/attachment_inspection.go`.
Regression coverage: `internal/core/mime_finding_budget_test.go`.

Local source checkout was blocked by DNS resolution of github.com. Exact-HEAD Go tests and isolated Postfix/Dovecot mail-host tests must complete before declaring regression qualification. These changes are not production-host acceptance.

## Open production gates

Issues #1–#9 remain open. Required acceptance includes real Postfix holds and mailbox disposition, durable delivery under faults, SMTP/authentication interoperability, measured clean/spam corpora and false-positive bounds, per-recipient tenant enforcement, retained diagnostics, browser acceptance, cold restore, and native update/rollback. Preserve /opt/spamgate/spamgate, spamgate-worker, /opt/spamgate/data, and Milter ports 38470/38472. No running mail host should be modified automatically.
