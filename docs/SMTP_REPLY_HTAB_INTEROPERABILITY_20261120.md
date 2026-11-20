# SMTP reply HTAB interoperability — 2026-11-20

## Scope
The passive SMTP diagnostic parser previously rejected every ASCII control byte, including horizontal tab in SMTP reply text. RFC 5321 reply text permits HTAB; the enhanced-status evidence parser already accepted HTAB as a delimiter. This change makes the wire reader consistent while preserving strict numeric reply-code and separator framing.

## Changes
- `internal/smtpprobe/probe.go`: permit HTAB only after the four-byte SMTP reply prefix; reject all other C0 controls and DEL.
- `internal/smtpprobe/reply_htab_test.go`: cover single-line, multiline, enhanced-status replies, invalid prefix tabs, NUL, ESC, DEL, bare LF, and embedded CR.
- No SMTP AUTH commands, credentials, delivery attempts, or mail-server configuration changes.

## Evidence and limitations
- Source change and regression test committed to `main`.
- Full repository Go tests and final-HEAD GitHub Actions outcomes are **not verified** in this pass; connector workflow lookup returns no matching runs and local checkout fails DNS resolution.
- This is interoperability hardening, not evidence of real Postfix/Dovecot disposition, production authentication compliance, classifier accuracy, tenant enforcement, or beta readiness.
- The permanent native launcher, worker, persistent data path, and Milter ports remain unchanged.
