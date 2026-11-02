# SpamGate native SMTP crash-retry ceiling — 2026-11-02

## Failure and fix

Issue #2 requires bounded at-least-once delivery after interrupted SMTP attempts. The durable worker increments `Attempts` and persists `delivering` **before** contacting the upstream SMTP server. Previously, when a worker crashed repeatedly while a relay was in flight, the recovery path could continue beyond `MaxDeliveryAttempts=16` because the limit was enforced only after a returned send error. Repeated crashes therefore bypassed the automatic retry ceiling.

The worker now inspects the persisted count immediately before starting another SMTP attempt. At or above 16, it durably parks the original as `dead` without another network send, preserves the immutable original and envelope, records an actionable `QUEUE_DELIVERY_ATTEMPTS_EXHAUSTED` history finding, and retains any previous upstream error. This applies to recovered `delivering` and retryable `queued` jobs, including older records already beyond the limit. Repeated worker restarts do not create duplicate findings or send the message. If history persistence fails, the dead-letter spool remains authoritative and no new send occurs.

An operator may explicitly use the existing audited/manual retry workflow to reset attempts and requeue the original. **That action may duplicate mail**: an interrupted SMTP attempt may have been accepted upstream before the local process crashed. The original and evidence must be reviewed before retrying.

## Verification and qualification boundary

`go test -count=1 ./internal/transport` exercises crash-retained `delivering` originals at and beyond the ceiling, `queued` originals at the ceiling, repeated recovery passes, immutable bytes/digests, one history finding, and explicit operator retry. Engineering CI runs the complete Go and race suites and the separate disposable Postfix/Dovecot integration workflow.

This is not a power-cut or production-host qualification. Disk-full faults, SMTP acknowledgement ambiguity, ISPConfig persistence, and the remaining issues #1-#9 require separate independent evidence. No live mail host is changed.

The native foreground launcher remains `/opt/spamgate/spamgate`, the worker remains `spamgate-worker`, persistent state remains `/opt/spamgate/data`, and Postfix Milter ports remain 38470/38472. No Docker substitution or automatic mail-server modification is introduced.
