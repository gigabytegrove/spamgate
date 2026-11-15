# Native HTTP worker security and recipient validation — 2026-11-14

## Scope

This change addresses two independently observed HTTP worker issues:

1. `Authorization` map keys inserted by middleware can use noncanonical casing. `http.Header.Values("Authorization")` does not enumerate these aliases. The worker now collects all case-insensitive keys and rejects duplicate, missing, empty, or conflicting credentials. Authentication remains bearer-token-only and the peer CIDR check still precedes token validation.
2. The exact prior HEAD `894e5d0685a25016925cd685c9e67a0f7af53c1f` failed engineering CI run [43665643300](https://github.com/gigabytegrove/spamgate/actions/runs/43665643300) at `TestRspamdRcptCasefoldRejectsInvalidAliases`: the mailbox identity parser accepted `not-an-address`. A conservative local-part/domain structural check now rejects that case, missing local parts, and missing domains.

## Tests

Added `rspamd_bearer_alias_test.go` with case-insensitive authorization collection and handler-level HTTP tests. Extended `rspamd_mailbox_identity_test.go` with malformed address regressions. Existing `rspamd_rcpt_casefold_test.go` is the CI reproduction.

The exact-final-HEAD engineering workflow and isolated Postfix/Dovecot workflow must finish successfully before considering these fixes verified in the complete repository. No production host was accessed or modified.

## Architecture and qualification

Preserve native `/opt/spamgate/spamgate` foreground launcher, `spamgate-worker`, `/opt/spamgate/data`, and Milter ports 38470/38472. No Docker substitution, no automatic Postfix/Dovecot changes. All production issues #1–#9 remain open pending host evidence and end-to-end acceptance, including hold/release, durable delivery, authentication interoperability, classifier precision, tenant isolation, UI, backup/restore, and update/rollback.
