# SMTPUTF8 mailbox identity hardening — 2026-11-15

## Scope
The Rspamd-compatible native HTTP worker validates sender and recipient envelope identities before scanning. This change narrows unquoted ASCII local parts to RFC 5321 dot-atom atext, while preserving valid quoted ASCII-space local parts and non-ASCII SMTPUTF8 local parts. Unicode whitespace, C0/C1 controls, format controls (including bidi overrides and zero-width joiners), and line/paragraph separators are rejected in all mailbox contexts. The existing domain-label and IPv4/IPv6 literal checks remain intact.

## Files
- internal/transport/rspamd_mailbox_structure.go — updated validator
- internal/transport/rspamd_smtputf8_security_test.go — 16 new cases

## Qualification boundary
This is a mailbox parser hardening change, not proof of RFC 6531 interoperability with real Postfix/Dovecot or an end-to-end SMTPUTF8 implementation. No live mail host was modified. A full package test, native build, real SMTPUTF8 message delivery, SMTP AUTH/STARTTLS, and exact-commit CI must pass before this change is considered qualified. Issues #1–#9 remain open.

## Locked native deployment
Keep /opt/spamgate/spamgate as the foreground launcher, spamgate-worker as the worker, /opt/spamgate/data as persistent storage, and Postfix Milter ports 38470/38472. No Docker replacement or automatic running-server changes.
