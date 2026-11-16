# Classifier corpus integrity: explicit tenant inventories and UTF-8 (2026-11-16)

## Changes

- An explicitly supplied `-expected-tenants=` can no longer silently disable tenant coverage. Empty, comma-empty, and whitespace-padded entries fail before reading or reporting corpus results. Omitting the flag remains supported for exploratory evaluations.
- The offline corpus validator rejects invalid UTF-8 bytes before JSON tokenization. Go's JSON decoder otherwise substitutes the Unicode replacement character for invalid byte sequences, potentially collapsing distinct sample identifiers and obscuring provenance.
- Regression tests exercise invalid options, valid/omitted inventories, malformed UTF-8 and fail-before-report behavior.

## Qualification boundaries

This is an offline evidence-integrity improvement, not a change to live mail classification or mail-host configuration. It does not prove classifier false-positive performance, live Postfix/Dovecot dispositions, durable delivery, SMTP authentication, tenant-policy lifecycle, browser acceptance, backup/restore, or native update/rollback. Those gates remain open pending end-to-end evidence. No native launcher, worker, data path, or Milter port changes are made.
