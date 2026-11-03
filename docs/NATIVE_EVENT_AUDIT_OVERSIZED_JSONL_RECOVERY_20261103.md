# Native event audit: oversized JSONL recovery (2026-11-03)

## Defect

The read-only `spamgate-event-audit` previously used `bufio.Scanner` with a 2 MiB token limit. A single oversized event terminated the complete analysis with a scanner error, hiding later evidence from the report. This is an availability and observability defect, not proof of mail disposition.

## Correction

`analyze` now reads newline-delimited records through a bounded `bufio.Reader.ReadSlice` loop, discards the remainder of any oversized record without retaining its payload, counts that record as malformed once, and resumes with subsequent records. Valid evidence after an oversized line remains reportable. Empty lines are ignored. An oversized final record without a newline is counted as malformed. Read errors other than EOF and buffer-full remain fatal.

## Regression

`go test ./cmd/spamgate-event-audit -count=1` covers oversized records followed by valid quarantine evidence, an unterminated oversized final record, and blank-line controls. The pre-existing JSON integrity regressions remain applicable.

## Qualification limitations

The audit reports requested Milter actions only. A quarantine count does not independently establish a Postfix HOLD, successful delivery, or Dovecot disposition. Correlate Postfix queue IDs, logs, and queue state on an isolated mail host. The 2 MiB line cap remains intentional. The read-only tool does not alter Postfix or Dovecot configuration. No Docker replacement, automatic mail-host change, or launcher change is authorized by this correction.
