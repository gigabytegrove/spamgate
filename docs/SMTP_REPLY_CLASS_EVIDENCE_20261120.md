# SMTP reply-class diagnostics — 2026-11-20

## Change
Issues #3 and #6: SMTP probe assessments now preserve an observed 4xx (temporary) or 5xx (permanent) response class for the greeting, initial EHLO, STARTTLS and post-TLS EHLO. A zero (unattempted) or 2xx/3xx code produces no class finding. The findings do not assert delivery, authentication, or retry success. No SMTP commands, Milter decisions, service configuration, or production mail hosts are changed.

## Implementation
- `internal/smtpprobe/smtp_reply_evidence.go`: pure classification, deterministic stage ordering, bounded numeric code in messages.
- `internal/smtpprobe/assessment.go`: add classification findings to the existing read-only assessment, including early greeting/EHLO exits.
- `internal/smtpprobe/smtp_reply_evidence_test.go`: table cases for observed 421/450/454/550/554, non-error/unattempted replies, single-stage findings and greeting assessment integration.

## Evidence and limits
The repository HEAD and existing SMTP assessment/probe were inspected through the authenticated GitHub connector. The source and tests were committed to main. GitHub Actions commit-run lookup returned no runs and combined commit statuses returned no statuses at the time checked; neither is evidence of success. A full checkout and Go test execution could not run in this environment because github.com DNS resolution failed. No real Postfix/Dovecot host was available or modified.

## Outstanding cumulative production gates
Issues #1–#9 remain open: real Milter/queue holds and Dovecot disposition, durable delivery and recovery, authentication conformance, classifier accuracy/false positives, tenant policy enforcement, historical diagnostics/alerts, complete browser-tested operations, native backup/restore and update/rollback. This change does not close any issue or qualify the beta. The October 31 target has passed.

## Locked deployment
Preserve permanent foreground launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, persistent `/opt/spamgate/data`, Postfix Milter ports 38470/38472, native Linux deployment, and read-only default against the running mail server.
