# Native Postfix inventory evidence boundary — 2026-11-17

## Scope and security correction

The inventory validator previously used a Go string literal containing double-escaped CR, LF, and NUL sequences. As a result, `strings.ContainsAny` tested for ordinary letters and backslashes rather than the intended control bytes. The correction uses actual `\r`, `\n`, and `\x00` escape sequences. This prevents malformed recipients from reaching HOLD queue correlation while avoiding rejection of an ordinary backslash solely because it is a backslash.

The native `postqueue -j` reader now calls `parseValidatedPostfixHold` before returning inventory. The browser and privileged release endpoints retain their own checks, including injected provider validation. This is defense in depth, not a claim that Postfix queue identity is cryptographically proven.

## Added regression cases

The inventory validator now covers carriage-return injection and a literal backslash recipient. Native JSON boundary fixtures cover valid and empty inventories, missing recipient evidence, escaped CR/LF/NUL, duplicate queue IDs, negative size, missing arrival, and malformed JSON.

## Verification and limitations

Commits were written to `main` using the GitHub connector. Local Git checkout failed because the execution host could not resolve `github.com`. The available local Go version was 1.23.2 while the repository previously required 1.27.4. No local compilation or tests are claimed. GitHub connector commit-status and PR-triggered workflow queries are not sufficient to establish push CI success. No production Postfix or Dovecot host was modified.

All issues #1–#9 remain subject to their independent acceptance gates, particularly live correlated HOLD release, actual mailbox disposition, durable recovery, SMTP/authentication compliance, classifier accuracy, tenant policy conflicts, operational UI, diagnostics, backup/restore and native update/rollback. Do not declare beta-qualified without end-to-end evidence.

Locked architecture remains the native foreground launcher `/opt/spamgate/spamgate`, `spamgate-worker`, persistent `/opt/spamgate/data`, and Milter ports 38470/38472. No Docker substitution or automatic mail-host configuration changes.
