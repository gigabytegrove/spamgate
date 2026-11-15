# Envelope identity fidelity gate — 2026-11-15

## Observed defect
The native Rspamd-compatible worker called strings.TrimSpace on the raw SMTP envelope identity before validating it. That silently transformed malformed sender and recipient values into accepted identities. The same parser rejected all commas, including legal quoted local parts such as `"last,first"@example.test`.

## Change
The parser now rejects leading/trailing whitespace instead of rewriting the identity, and delegates comma placement to the existing mailbox-structure validator. The only supported transformations remain removal of one complete SMTP path wrapper and mapping an allowed null reverse-path to the empty sender. No mail host is reconfigured.

## Regression coverage
- 17 direct mailbox boundary cases (including quoted and escaped commas, malformed wrappers, null sender, whitespace)
- 7 HTTP metadata integration cases (recipient and sender paths)
- Existing adversarial and SMTPUTF8 regression tests retained

## Qualification evidence and limits
Source changes and tests committed to main. Local repository checkout cannot resolve github.com in the execution environment, so full-package tests and native build are not locally verified. GitHub Actions must complete on the exact final commit. No real Postfix/Dovecot host has been qualified; no delivery/hold/rollback acceptance is implied. Issues #1–#9 remain open.

## Locked architecture
/opt/spamgate/spamgate foreground launcher; spamgate-worker; persistent /opt/spamgate/data; Postfix Milter ports 38470/38472. Native Linux only, no Docker substitution, no automatic changes to the running mail server.
