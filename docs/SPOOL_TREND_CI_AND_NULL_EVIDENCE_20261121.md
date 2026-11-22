# Spool trend: compiler regression and null evidence rejection (2026-11-21)

## Verified defect
The engineering workflow for commit `f93199545ba2b58a479f15ef066ad91a4a5b541b`, run [44959136294](https://github.com/gigabytegrove/spamgate/actions/runs/44959136294), failed during Go unit/race tests before executing the spool-trend tests. The compiler reported `internal/spooltrend/trend.go:64:10: no new variables on left side of :=`. The report reader redeclared `data,err` after both variables already existed. Commit `82826a76fe5404ffd307ed8f798b0fe915ef2971` changes the re-marshalling statement to assignment.

## Evidence integrity
Mandatory fields `gate_passed`, `examined`, `published`, `pending`, `states`, `findings`, and `truncated` must be present and non-null. Previously JSON `null` decoded into zero values for several Go scalar fields, which could misrepresent evidence as a clean empty queue. The reader now rejects explicit null values before typed decoding. Regression cases cover each nullable field. Additional fields remain forward-compatible, while duplicate JSON keys, malformed JSON and inconsistent state counts remain rejected.

## Qualification boundary
These changes do not prove mail delivery, Postfix/Dovecot disposition, queue snapshot authenticity, or host-level acceptance. CI for the final commit must be checked separately; a successful earlier run cannot qualify newer commits. No running mail server or configuration is modified by these read-only diagnostic changes.
