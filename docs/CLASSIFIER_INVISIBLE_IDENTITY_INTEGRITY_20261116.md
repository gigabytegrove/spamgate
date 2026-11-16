# Classifier corpus identity canonicalization — 2026-11-16

Offline qualification rejects leading/trailing Unicode whitespace in sample IDs and tenant identifiers, and rejects Unicode control and format characters (including zero-width joiners and bidirectional overrides) anywhere in those identifiers. This avoids visually indistinguishable provenance keys and tenant labels that could split qualification counts or obscure evidence review. Ordinary non-ASCII identifiers and interior spaces remain valid. This affects only the offline evaluator, not the production classifier or mail flow.

Regression coverage: `cmd/spamgate-classifier-eval/corpus_invisible_identity_test.go` tests whitespace, JSON-escaped control characters, format characters, valid Unicode, and fail-before-report behavior. This change does not prove classifier precision/recall or production-host safety.

Outstanding gates: issues #1–#9 remain open. Native foreground `/opt/spamgate/spamgate`, `spamgate-worker`, persistent `/opt/spamgate/data`, Milter ports 38470/38472, no Docker substitution, and no automatic live mail-server changes remain unchanged. Production Postfix/Dovecot, SMTP authentication, durable delivery, tenant enforcement, UI, diagnostics, backup/restore and native rollback require independent end-to-end evidence.
