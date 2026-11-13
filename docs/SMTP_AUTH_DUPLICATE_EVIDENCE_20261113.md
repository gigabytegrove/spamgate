# SMTP AUTH duplicate-mechanism evidence gate — 2026-11-13

## Implementation
The read-only SMTP EHLO parser now rejects repeated AUTH mechanism names within a single advertisement, including case-insensitive repetitions and the historical AUTH= form. Repeated names make the AUTH mechanism set untrustworthy; the parser returns an empty mechanism set rather than treating the surviving unique names as verified evidence. The EHLO warnings include the stable identifier `DUPLICATE_AUTH_MECHANISM`. Duplicate AUTH extension lines remain rejected independently.

This is intentionally diagnostic-only: no AUTH commands, passwords, MAIL FROM, RCPT TO, or DATA are sent. It does not change Postfix, Dovecot, delivery, Milter behavior, or production settings.

## Regression coverage
`internal/smtpprobe/auth_duplicate_test.go` exercises unique mechanisms, identical duplicates, case-folded duplicates, legacy AUTH= duplicates, duplicates mixed with other mechanisms, repeated AUTH lines, and absence of AUTH.

## Evidence and qualification boundaries
The last preceding HEAD `2332cad178630efd35be201cbd9963b6bd650c77` passed engineering qualification (run 43438878240) and the isolated Postfix/Dovecot lab (run 43438878327). Those results **do not** qualify the new commit. Local checkout and Go execution were blocked by GitHub DNS resolution in the automation environment. New-HEAD CI must be inspected separately. No real production mail-host acceptance evidence exists for this change.

Open production issues #1–#9 remain cumulative gates. This change addresses one narrow SMTP/authentication diagnostic integrity defect; it is not evidence of successful SMTP AUTH interoperability or a beta release.
