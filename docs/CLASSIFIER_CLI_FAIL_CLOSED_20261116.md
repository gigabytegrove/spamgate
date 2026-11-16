# Offline classifier CLI fail-closed input validation — 2026-11-16

The offline `spamgate-classifier-eval` is not a production classifier or mail-disposition engine.

## Corrected behavior

Explicitly supplied acceptance flags `-max-fp-upper`, `-min-recall`, and `-min-precision` must be finite and within [0,1]. A negative supplied value now errors rather than silently disabling the gate. The default -1 sentinel continues to mean no gate when the option is omitted. `-audit-boundary-margin` must be finite and nonnegative when supplied. Explicit minimum sample sizes must be positive, and explicitly supplied z scores must be finite and in (0,10]. Invalid options fail before corpus input is consumed or any report is emitted.

The JSON corpus is read with a hard 32 MiB byte limit, including trailing whitespace or JSON data. Oversized inputs fail before evaluation, rather than potentially being accepted when the decoder encounters EOF at a truncated input boundary.

## Regression coverage

`go test ./cmd/spamgate-classifier-eval ./internal/qualification` exercises invalid/NaN/infinite options, explicitly supplied zero false-positive limit, and exactly-at/over corpus-size boundaries. A successful test does not demonstrate classifier detection accuracy.

## Qualification boundaries

Run the complete engineering and isolated mail-host CI against the exact commit. Separately qualify actual production classifier scores on independently labeled tenant-representative data, including MIME/archive and phishing families, with false-positive, recall and precision acceptance. Postfix/Dovecot hold and release, durable delivery, SMTP/authentication, tenant policy enforcement, browser UI, backups and native rollback still need real end-to-end evidence. No production mail server is modified by this change.
