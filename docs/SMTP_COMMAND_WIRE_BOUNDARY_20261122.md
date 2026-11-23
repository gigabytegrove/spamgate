# Native SMTP wire-command boundary — 2026-11-22

Issue #3 (SMTP conformance), issue #2 (acceptance safety), issue #6 (diagnostics).

## Defect
The command handler previously applied strings.TrimSpace to an incoming SMTP command before dispatch. This silently promoted malformed commands with leading/trailing whitespace, tab/control characters and ambiguous multiple separators into valid commands. The greeting validator had been corrected separately, but MAIL, RCPT, XFORWARD and command-only verbs still shared the normalization boundary.

## Change
Validate the original command line before dispatch; require printable ASCII, alphabetic command verb, one space between verb and arguments, and no leading/trailing spaces. Preserve all original argument bytes for downstream path/parameter validation. Reject malformed lines with 500 without changing the SMTP session or envelope state. Keep the existing 512-byte command bound and read deadlines.

## Qualification
Source change and socket-level regression tests committed. NOT EXECUTED: Go compilation, test suite, owner-controlled native Linux build, real Postfix/Dovecot integration, failure injection, and production mail-host qualification. No mail-server or service changes. No GitHub Actions.

## Open gates
Issues #1–#9 remain open. In particular, durable delivery failure injection, authentication interoperability, classifier false-positive corpus, tenant policy conflicts, UI acceptance, backup/restore and native update/rollback require separate implementation and independent evidence.
