# Native Postfix HOLD release: worker reconciliation barrier (2026-11-17)

## Change
The unprivileged worker now maps **every failed launched release subprocess** to a stable, confidential indeterminate-outcome sentinel. The narrow root-owned helper's exit 70 is included, as are exit 64, sudo failure, cancellation and process-launch errors. A nonzero process exit cannot establish that no queue mutation occurred. The API persists `release_attempted` before execution and refuses subsequent release attempts for that scan; failed execution appends `POSTFIX_HOLD_RELEASE_OUTCOME_UNKNOWN` to the durable findings and returns an explicit reconciliation instruction. Failure to persist the additional finding is logged, while the pre-execution durable intent remains the retry barrier.

Successful subprocess stdout and stderr are not forwarded into API responses. The privileged helper's fixed output remains an implementation detail, not mailbox-delivery evidence. A success is still `release_submitted`, not delivered.

## Qualification and boundaries
- Added tests for helper exit 70/64, wrapped failures, startup failure, nil and private diagnostic non-disclosure.
- The existing HTTP and queue-correlation tests must pass on exact HEAD before this change can be accepted.
- No automatic reconciliation, queue-identity proof across Postfix queue-ID reuse, or safe automatic retry is implemented. Operators must correlate queue ID, complete envelope, arrival timestamp, scan evidence and Postfix logs independently before manual intervention.
- Live Postfix/Dovecot/ISPConfig acceptance, end-to-end HOLD-to-mailbox evidence, multi-worker fault injection and disaster recovery remain outstanding under issues #1, #2, #8 and #9.
- No running mail-host configuration was changed. The permanent launcher remains /opt/spamgate/spamgate, worker spamgate-worker, data /opt/spamgate/data and Milter ports 38470/38472. No Docker substitution.

## Evidence
Starting HEAD: f8bc2cbf98428938fc2f9adba47a693998593dc0 (previous engineering and isolated laboratory workflows passed). Implementation commits: cb7c458cb43d05e234e2300ff74280df17f0099d, 5490a5a0717d1cd096fc0192180b050ee63832e0, 2d76c2efd85dd3466ee6938f792d261686738aa6. Exact-final-HEAD workflow conclusions must be independently inspected; queued/pending is not a pass. Local Go execution unavailable because the local toolchain is Go 1.23.2 while the module declares 1.27.4.
