# SMTP SIZE presence evidence integrity — 2026-11-13

## Change
The read-only SMTP assessment no longer reports SIZE appearance/disappearance across STARTTLS when either initial or post-TLS SIZE parsing reports ambiguous, malformed or contradictory evidence. Numeric SIZE-limit drift already required clean SIZE evidence; presence transitions now apply the same trust boundary. Valid, observed changes remain visible after verified STARTTLS and successful post-TLS EHLO.

## Regression
`internal/smtpprobe/assessment_size_presence_integrity_test.go` covers eight presence/ambiguity scenarios and three TLS/EHLO preconditions. No SMTP credentials or messages are transmitted by this diagnostic.

## Qualification
Source committed to main; regression execution and exact-HEAD CI must be inspected separately. This change is not proof of SMTP authentication, mail delivery, production-host behavior, classifier quality or beta acceptance. Native launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, persistent `/opt/spamgate/data`, and Postfix Milter ports 38470/38472 are unchanged. No running mail-server configuration was modified.

## Open gates
GitHub issues #1-#9 remain subject to their individual acceptance criteria, including real Postfix/Dovecot disposition, durable delivery, tenant policy, classifier false positives, browser operations, cold restore and native update/rollback. The October 31 beta target has passed without real-host qualification.
