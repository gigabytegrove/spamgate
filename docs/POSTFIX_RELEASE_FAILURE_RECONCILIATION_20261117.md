# HOLD-release post-execution failure reconciliation — 2026-11-17

Starting HEAD: `4cfb02e8dab9c467aaccb9382fa1c83f7a34d659`.

## Defect and correction

The helper previously marked reporting failures and cancellation as indeterminate, but an executed `postsuper -H` returning a nonzero status or producing excessive output was not marked indeterminate. A nonzero status does not prove that Postfix made no queue-state change. The worker must not treat such failures as safe to retry.

All failures after starting the child command now wrap `errReleaseOutcomeUnknown`, including nonzero exit and bounded-output overflow. `errOutputLimit` and typed subprocess exit status remain detectable with `errors.Is` / `errors.As`. Error text still excludes child stdout/stderr. Pre-execution cancellation and input validation remain distinct.

The helper's external process protocol still uses an exit code and diagnostic text, not a durable machine-readable outcome record. Worker-side reconciliation, identity verification, and retry suppression remain mandatory before declaring issue #1 complete.

## Verification and acceptance boundary

New Linux tests use disposable subprocesses to exercise failed exit, output overflow, confidentiality, and pre-execution failures. The tests do not modify Postfix. GitHub Actions must run against the final commit before reporting a pass. The isolated VM laboratory is not evidence of production-host acceptance.

No live mail-server settings were changed. Native launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, data directory `/opt/spamgate/data`, and Milter ports 38470/38472 remain unchanged. Issues #1–#9 remain open. The October 31 beta target has passed; beta readiness is not established.
