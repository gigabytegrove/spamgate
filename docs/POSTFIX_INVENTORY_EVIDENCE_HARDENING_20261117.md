# Postfix HOLD inventory evidence hardening — 2026-11-17

## Scope

The browser's read-only HOLD queue endpoint now validates inventory from both native postqueue and injected inventory providers before presenting scan correlations. An invalid provider result returns HTTP 503 and does not expose purported queue ownership or change Postfix.

The shared release authorization validator rejects more than 1000 HOLD entries, more than 50 recipients per entry, truncated recipient evidence, mismatched counts, invalid/duplicate queue identifiers, missing arrival timestamps, negative message sizes, and recipient addresses with padding, CR/LF, or NUL. This is intentionally fail-closed: an oversized queue must be inspected by an operator on the mail host. These limits are for authorization evidence, not SMTP delivery limits.

## Commits and tests

Changed `internal/server/postfix_hold.go`, `internal/server/postfix_release_inventory.go`, and `internal/server/postfix_release_inventory_test.go`. Added regression cases for padded recipient addresses, CR/LF/NUL contamination, oversized inventory, and recipient evidence exceeding 50.

GitHub commits were accepted. Local checkout was blocked by GitHub DNS resolution, so no local Go tests were run. GitHub commit-status and PR-only workflow lookups returned no runs or statuses; neither response establishes passing push-triggered CI. No production Postfix/Dovecot acceptance was performed.

## Remaining acceptance gates

Issues #1–#9 remain unqualified. This pass does not prove queue identity after a release attempt, downstream mailbox placement, durable delivery and crash recovery, SMTP/authentication compliance, classifier false-positive rates, tenant policy enforcement, diagnostics, complete browser acceptance, backup/restore, or native update/rollback.

Locked architecture unchanged: permanent foreground launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, persistent `/opt/spamgate/data`, Milter ports 38470 and 38472. No Docker substitution and no automatic changes to a running mail server.
