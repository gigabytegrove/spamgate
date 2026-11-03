# Labelled corpus resource budget — 2026-11-03

The native `spamgate-eval` classifier evaluator now enforces `--max-records` (default 1,000,000, positive integer). Each nonempty JSONL record counts against the budget; blank lines do not. Exceeding the budget aborts without emitting a misleading partial confusion matrix. This bounds the number of retained unique SHA-256 identifiers when `--require-unique-ids` is enabled and bounds evaluation work for hostile or accidental oversized corpora. The existing 64 KiB per-record limit remains.

The limit is configurable for intentionally larger independently adjudicated corpora. This is an evaluator safety change only, not evidence of classifier accuracy or live mail-host qualification. Regression coverage checks exact-limit success, over-limit rejection, blank lines, and invalid budgets.

All nine production gates remain open. No running Postfix/Dovecot configuration, Milter ports, native launcher, worker, or persistent data layout is changed.
