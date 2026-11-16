# Postfix HOLD release failure audit confidentiality — 2026-11-16

## Confirmed source defect

The failed privileged Postfix HOLD release path previously appended `err.Error()` directly to a persisted `core.Finding` in the message record. That message record may be displayed through authenticated message investigation APIs. Privileged helper execution errors can contain host paths, sudo configuration, and other operational details. The HTTP failure response was already sanitized, but the durable finding was not.

## Change

Persist a fixed, actionable failure detail instead of the privileged error. Retain the original error in the server-side structured log. The durable `release_attempted` state and fail-closed retry semantics are unchanged. The system does not infer delivery from helper execution.

## Qualification

The new regression test checks that the persisted finding detail is nonempty, actionable and independent of representative privileged errors. The test does **not** constitute production-host qualification or prove end-to-end privileged helper release, queue ownership, Dovecot delivery, or ISPConfig persistence.

No mail server configuration is modified by this change. Required native paths remain `/opt/spamgate/spamgate`, `spamgate-worker`, and persistent `/opt/spamgate/data`; Milter ports remain 38470/38472.

Issues #1–#9 remain subject to their existing acceptance gates.
