# SMTP recipient authorization boundary — 2026-11-22

## Change
The recipient-domain allowlist now refuses malformed internal recipient strings (missing local part, missing domain, multiple at-signs), and validates ASCII DNS domain syntax before comparing against configured allowed domains. Uppercase ASCII domain names remain authorized by case-insensitive comparison. Non-ASCII domain bytes are refused rather than Unicode-folded into an allowed ASCII name.

## Regression coverage
`TestSMTPRecipientAuthorizationRejectsMalformedEnvelopes` covers ordinary and uppercase domains, empty components, multiple at-signs, Unicode Kelvin/fullwidth lookalikes, trailing dots, malformed labels and CRLF. `TestSMTPRecipientAuthorizationNeverUsesLastAtSign` specifically prevents the former last-at-sign authorization ambiguity.

## Qualification evidence
GitHub commits are published. No successful Go test or build execution has been observed for this change. The repository declares Go 1.27.4. GitHub commit status and the available pull-request workflow lookup returned no results at inspection; this does not establish that push-triggered workflows did or did not run.

## Outstanding gates
Issues #1–#9 remain unresolved as production acceptance gates: actual Postfix/Dovecot holds and disposition; durable delivery and crash/failure recovery; SMTP/authentication interoperability; classifier accuracy and false positives; tenant isolation; diagnostics; browser UI; backup/restore; native update and rollback. Real-host end-to-end evidence is absent. This is not beta qualification.

## Architecture
No deployment, Docker substitution, Postfix/Dovecot reconfiguration or service restart. Permanent foreground launcher /opt/spamgate/spamgate, spamgate-worker, /opt/spamgate/data, and Milter ports 38470/38472 remain unchanged.
