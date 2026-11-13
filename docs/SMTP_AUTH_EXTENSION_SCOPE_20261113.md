# SMTP AUTH duplicate-extension scope — 2026-11-13

## Defect
EHLO capability validation emits a generic `DUPLICATE_EXTENSION` for any repeated keyword. The AUTH assessment previously treated that generic warning as proof of untrustworthy AUTH evidence, even when the repeated keyword was SIZE or PIPELINING. That suppressed legitimate AUTH mechanism drift findings.

## Change
The capability parser now additionally emits `DUPLICATE_AUTH_EXTENSION` only when the repeated canonical extension is AUTH (including mixed AUTH and AUTH= forms). The assessment treats this scoped warning, duplicate/malformed AUTH mechanisms, and empty AUTH advertisements as ambiguous authentication evidence. The generic `DUPLICATE_EXTENSION` remains for other diagnostic consumers.

## Regression scope
The new tests exercise repeated SIZE, PIPELINING, AUTH, mixed AUTH syntaxes, clean evidence, and a verified STARTTLS comparison where unrelated duplicate capability evidence must not suppress observed AUTH mechanism changes.

## Qualification
Source committed to main; Go test execution, exact-HEAD CI and real Postfix/Dovecot host qualification must be independently verified. This is a read-only SMTP diagnostic change. No credentials are sent and no mail-host configuration is modified. Issues #1–#9 remain open; no beta acceptance is implied.
