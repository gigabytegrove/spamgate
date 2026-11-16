# Classifier corpus JSON integrity — 2026-11-16

The offline `spamgate-classifier-eval` command now rejects duplicate JSON object keys before it decodes labeled samples. Duplicate keys could otherwise overwrite `spam`, `score`, `tenant`, or `id` and silently change acceptance evidence. The check applies recursively to nested objects and treats Unicode-escaped equivalent keys as duplicates. Nesting deeper than 64 levels is rejected. Existing 32 MiB input budget, unknown-field rejection, and evaluation gates remain intact.

## Regression coverage

`go test ./cmd/spamgate-classifier-eval` exercises duplicate labels, scores, tenant IDs, sample IDs, nested duplicate keys, escaped-equivalent keys, valid input, and trailing JSON. No live mail flow or policy is changed.

## Qualification boundary

This is a corpus-integrity safeguard, **not** proof of independently verified labels, classifier detection accuracy, production SMTP integration, or end-to-end Postfix/Dovecot delivery. Production mail-host acceptance and all issue #1–#9 gates remain outstanding until demonstrated with evidence. The permanent foreground launcher `/opt/spamgate/spamgate`, `spamgate-worker`, persistent `/opt/spamgate/data`, and Milter ports 38470/38472 are unchanged.
