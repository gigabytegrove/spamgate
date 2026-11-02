# Native Milter SMTP temporary-failure enforcement — 2026-11-02

## Production defect

The Milter scanner correctly persisted `soft_reject` and
`smtp_temporary_failure_requested` after a greylist or rate-limit decision,
but the final Milter response switch lacked a `soft_reject` case. It fell
through to `SMFIR_CONTINUE` (`c`). This allowed mail that the audit trail
claimed had been temporarily refused to proceed to Postfix.

## Corrected contract

* `soft_reject` returns `SMFIR_TEMPFAIL` (`t`) at end-of-message.
* `reject` returns `SMFIR_REJECT` (`r`).
* `accept` alone returns an unconditional `SMFIR_CONTINUE` (`c`).
* `tag` and `quarantine` retain their existing capability-gated
  header/hold behavior; missing negotiated capabilities still tempfail.
* Unrecognized scanner actions are recorded as attempted SMTP temporary
  failures and return `t`, not implicit acceptance.
* A policy persistence error returns `t` without recording an
  uncommitted message verdict.
* New wire-level regressions cover rate-limit exhaustion, persisted state
  across worker restart, and failed policy persistence. These assertions
  inspect the actual Milter response, not only the audit event.

## Qualification boundary

These are in-process Milter wire tests and CI regression gates. The exact
Postfix SMTP 4xx response, queue disposition, retry schedule, real mail-host
behavior and multi-tenant false-positive impact still require independent
Postfix/Dovecot and production ISPConfig qualification. No mail-host settings
are changed by this patch. Native launcher, worker, persistent data path and
Milter ports remain unchanged.
