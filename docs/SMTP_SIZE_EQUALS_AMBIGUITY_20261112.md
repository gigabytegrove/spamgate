# SMTP SIZE equals-form ambiguity — November 12, 2026

## Defect and correction

The independent read-only SMTP probe previously ignored malformed `SIZE=123` EHLO extension lines. When a later valid `SIZE 456` line appeared, the parser could report a trusted limit despite the ambiguous advertisement. This patch recognizes the malformed equals-form, emits `MALFORMED_SIZE_ADVERTISEMENT`, and treats a combination with another SIZE advertisement as `DUPLICATE_SIZE_ADVERTISEMENT`. Neither case produces a trusted numeric limit. A SIZE-like string in the first EHLO identity line remains excluded.

## Scope and evidence

This change affects diagnostic interpretation only. It does not send AUTH, MAIL FROM, RCPT TO or DATA, does not modify Postfix/Dovecot configuration, and does not assert delivery or mail-host readiness. Regression cases cover malformed equals forms, duplicate ordering, case folding, server identity exclusion, unrelated keywords and valid SIZE.

The permanent native foreground launcher, worker, persistent data directory and Milter ports are unchanged. Exact-commit CI and real-host evidence must be recorded separately; tests existing in source are not evidence of their successful execution.
