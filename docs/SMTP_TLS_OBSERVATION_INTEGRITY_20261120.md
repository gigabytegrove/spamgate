# SMTP TLS observation-time integrity — 2026-11-20

## Change
The passive SMTP diagnostic now records `tls_observed_at` (UTC) at the completed verified TLS handshake. The certificate expiry-day calculation uses that same timestamp, avoiding a split-clock observation. The evidence assessor flags contradictions between the recorded timestamp, certificate NotAfter, and expiry-day sentinel. Historical observations are evaluated against their recorded time, not the current clock.

## Scope and boundaries
Files: `internal/smtpprobe/probe.go`, `internal/smtpprobe/tls_evidence.go`, `internal/smtpprobe/tls_observation_test.go`. This is passive SMTP evidence only; no credentials are submitted, no mail is accepted or delivered, and no Postfix/Dovecot configuration changes occur. Older results without a timestamp retain the previous evidence behavior.

## Qualification
Source committed on main. Six table-driven contradictory/consistent evidence cases and one archived-evidence regression were added. Full Go compilation and test execution are **unverified**: the available runtime has Go 1.23.2 while go.mod requires Go 1.27.4; GitHub DNS resolution failed during checkout. GitHub workflow lookup for final HEAD is restricted to pull-request-triggered runs and returned none; commit statuses returned none. Neither is proof of passing CI.

## Remaining production gates
Issues #1–#9 remain subject to actual production-host and end-to-end qualification: Postfix/Dovecot holds/disposition, durable delivery, SMTP/auth compliance, classifier precision/recall and false positives, tenant policy, operational diagnostics, browser workflows, backup/restore, and native update/rollback. This change does not qualify any of those production gates or long-term beta readiness.
