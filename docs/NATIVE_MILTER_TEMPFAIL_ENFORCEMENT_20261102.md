# Native Milter disposition and policy regression — 2026-11-02

## Verified source defect and change

Before this change, the final Milter action switch returned
`SMFIR_CONTINUE` for **any** action not explicitly listed, including
unrecognized forced actions from legacy or offline-edited rules. The
HTTP rule endpoint validates actions, but the core configuration update
path does not enforce that allowlist. An unexpected action could therefore
be recorded in history and silently delivered by Postfix.

The terminal Milter switch now permits unconditional continuation only
for the explicit `accept` action. Unknown scanner actions return
`SMFIR_TEMPFAIL` (`t`) and record an attempted SMTP temporary failure.
The `tag` and `quarantine` cases remain capability-gated.

The existing `soft_reject` branch **already** returned `t` before this
patch; it was not the discovered defect. New in-process Milter wire
regressions now assert that rate-limit exhaustion actually emits `t`
rather than trusting only the stored MTAAction. They also test
enforcement after worker restart and fail-safe behavior when policy
persistence fails. A forced unknown-action regression proves that
legacy/offline configuration cannot implicitly continue delivery.

## Operational and qualification boundary

* No change to the native foreground launcher, worker, persistent data
  directory, Milter ports or running mail-server configuration.
* `MTAActionState=requested` remains an intended command, not a
  confirmed Postfix SMTP response or mailbox delivery.
* The unknown-action fallback is defense in depth. Shared validation
  for all offline configuration import paths remains future work.
* In-process Milter wire tests are not independent production Postfix,
  ISPConfig or Dovecot qualification. Exact SMTP 4xx and retry behavior,
  multi-recipient behavior, and real-host failure injection remain open.
