# Transaction-safe recipient threshold parity — 2026-10-30

## Defect and implementation

Scanner and read-only policy preview used separate selection logic, requiring exactly one envelope recipient to apply a mailbox threshold. Duplicate addresses and distinct mailboxes with identical effective thresholds incorrectly fell back to global settings.

Both now call `core.SelectRecipientThresholds`. Every recipient resolves to configured mailbox thresholds or global defaults. A mailbox override applies to the whole SMTP transaction **only when all effective threshold triples match**. Conflicts always use global thresholds and record a clear trace/preview reason. The original delivery envelope and recipient count are not modified.

The separate all-recipient rule for `recipient_email` custom filtering remains unchanged. This is not recipient splitting or a guarantee of per-mailbox delivery, and the existing case-insensitive local-part matching still needs independent SMTP interoperability qualification.

## Gates

Run `go test ./internal/core ./internal/server -count=1`, `go test -race ./...`, `go vet ./...` and inspect exact-commit GitHub engineering and isolated Postfix/Dovecot integration. Real-host Milter, Sieve, hold/release, and multi-recipient policy tests remain required. Do not automatically change production Postfix configuration.
