# SMTP envelope capability evidence — 2026-11-12

## Scope

Read-only relay diagnostics now report SMTPUTF8, 8BITMIME, PIPELINING, SIZE, and AUTH advertisements after the applicable TLS negotiation. EHLO identity lines are excluded, and malformed extension keywords are ignored. SMTP AUTH mechanisms remain separately parsed.

## Safety

The probe sends EHLO, optionally STARTTLS and EHLO again, and QUIT. It does not send credentials, MAIL FROM, RCPT TO, DATA or alter Postfix/Dovecot. Capability advertisements do not demonstrate correct SMTPUTF8 envelope handling, 8-bit body transfer, pipelined transactions, SIZE enforcement, successful authentication or durable delivery.

## Verification requirements

Run exact-HEAD Go tests and isolated Postfix/Dovecot lab; review their logs. Validate real host integration only on an explicitly approved test host. Measure false positives and restore/rollback separately. Issues #1–#9 remain open until their own acceptance evidence exists.

## Locked runtime

Native launcher /opt/spamgate/spamgate, worker spamgate-worker, persistent /opt/spamgate/data, Milter ports 38470 and 38472. No Docker substitution or automatic live MTA changes.
