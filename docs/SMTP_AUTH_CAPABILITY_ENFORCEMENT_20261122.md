# SMTP AUTH capability enforcement — 2026-11-22

## Scope

Native Linux outbound SMTP relay, production issue #3. This is a source-level security correction, not production-host qualification.

The relay now checks the **post-TLS EHLO** AUTH mechanism list before calling Go's `smtp.Client.Auth` with PLAIN credentials. It requires an explicit `PLAIN` token (case-insensitive, whitespace-delimited). An absent AUTH extension, LOGIN-only, CRAM-MD5-only, or misleading XPLAIN advertisement fails before the AUTH command and before MAIL FROM/RCPT/DATA. The check is not applied to unauthenticated relays.

The existing TLS requirement remains mandatory for configured credentials. No downgrade, new credential storage, or change to Postfix/Dovecot configuration is introduced. No live mail service was touched.

## Regression evidence and boundaries

`internal/transport/relay_auth_capability_test.go` uses loopback TCP SMTP peers and checks the EHLO capability decision and absence of any AUTH or other subsequent SMTP command. It covers absent AUTH, LOGIN, CRAM-MD5, PLAIN, mixed mechanisms, mixed case, lookalike mechanism, unrelated SIZE, and nil client.

The previous main HEAD `b57ff31da4438705b475543ac3d534fdf3290c53` passed engineering run 45005146852 and isolated Postfix/Dovecot lab 45005146860. Those results **do not** validate these new commits. Fresh push-triggered CI must be inspected at the final HEAD. Unit tests and loopback peers do not prove an actual authenticated TLS submission to a production relay. Production issue #3 stays open.

## Remaining gates

Issues #1–#9 remain cumulative and open: real Postfix/Dovecot hold and mailbox disposition, durable acceptance and replay under crashes, full protocol/authentication interoperability, classifier false-positive corpus qualification, tenant policies, end-to-end diagnostics, browser acceptance, cold backup/restore, native update and rollback. The October 31 target has passed without beta qualification.

Locked runtime: `/opt/spamgate/spamgate` foreground launcher, `spamgate-worker`, persistent `/opt/spamgate/data`, Milter ports 38470 and 38472. No Docker substitution and no automatic running-mail-server changes.
