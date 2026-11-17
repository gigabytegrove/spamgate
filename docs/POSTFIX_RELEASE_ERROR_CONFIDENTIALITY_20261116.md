# Postfix privileged release error confidentiality — 2026-11-16

## Production gate
Issue #9 remains open. The optional native Linux `spamgate-postfix-release` helper invokes a fixed `/usr/sbin/postsuper -H <queue-id>` only through an explicit root privilege grant. This change does not install privileges, alter Postfix/Dovecot, or change the foreground launcher/worker architecture.

## Defect and correction
Previously, `runPostsuperCommand` appended sanitized but otherwise unredacted child stderr to its returned error. Sanitizing terminal controls does **not** remove sensitive envelope addresses, queue metadata or filesystem paths. The unprivileged worker can surface the helper failure, so this was an avoidable diagnostic disclosure path.

Failed subprocesses now return only the wrapped Go process error (including the exit status), without either stdout or stderr. The existing shared 8192-byte output budget, process-group cancellation and 8-second deadline are unchanged. Successful subprocesses retain the existing sanitized, bounded operator report. Reporting sinks are still validated before any privileged action.

## Regression evidence
`output_confidentiality_test.go` runs disposable local shell scripts (never actual Postfix) to verify that an exit-42 failure cannot expose stdout/stderr secrets, a successful invocation preserves its report, and a missing sink prevents execution. The tests require Linux and do not grant privilege.

## Qualification boundary
This is source-level confidentiality hardening, **not** proof that a held message was released, that queue ownership/reuse checks are correct, or that ISPConfig and Dovecot Sieve operate correctly on a production mail host. Real-host acceptance and independent browser/API privilege mediation remain outstanding. Check exact-final-HEAD engineering and isolated mail laboratory CI before claiming even regression qualification.
