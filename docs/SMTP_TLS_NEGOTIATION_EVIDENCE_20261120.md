# SMTP TLS negotiation evidence — 2026-11-20

Scope: passive SMTP diagnostics (issues #3 and #6). No SMTP AUTH, MAIL FROM, RCPT TO, DATA, Postfix configuration, or mail delivery is performed.

Starting main: e9477bd44fba549bbadd19af32059260475bc2e4.

The probe now retains the negotiated TLS cipher-suite name and number of verified certificate chains alongside the existing TLS version and certificate metadata. It explicitly records that the diagnostic did not perform mutual TLS authentication. Assessment emits diagnostic integrity warnings for manually constructed results lacking cipher or chain evidence, unknown cipher names, legacy cipher suites, or unexpected client-auth claims. These are observations, not proofs of authentication or compliance.

Source files: internal/smtpprobe/probe.go, assessment.go, tls_evidence.go, tls_evidence_test.go.

The permanent native launcher /opt/spamgate/spamgate, worker spamgate-worker, persistent /opt/spamgate/data, and Milter ports 38470/38472 remain unchanged. No Docker replacement or automatic mail-host changes.

Verification limits: GitHub commits are published. Local checkout is blocked by GitHub DNS resolution; full Go tests and real-host qualification were not executed locally. Exact-HEAD CI must be inspected independently. Issues #1–#9 remain open. The 2026-10-31 beta deadline has passed; do not claim beta readiness.
