# Classifier corpus field alias integrity — 2026-11-16

The Go JSON decoder accepts case-insensitive struct-field aliases. A corpus record with both `spam` and `Spam`, or `score` and `Score`, can overwrite the evidence used for offline false-positive, precision, and recall acceptance. Duplicate-key rejection alone does not catch these distinct JSON keys.

The schema validator now accepts only the exact lowercase fields `id`, `tenant`, `spam`, and `score`. All other fields, including case aliases, are rejected before evaluation or report output. This is deliberately fail-closed and applies to exploratory and gated evaluation.

Regression coverage includes case aliases, Unicode-escaped aliases, unrelated unknown fields, and a valid exact-schema sample.

This does not prove classifier accuracy, a representative corpus, or live Postfix/Dovecot disposition. Run the complete Go regression suite and isolated mail laboratory, then independently qualify a real host before beta acceptance. No running mail-server configuration is changed.
