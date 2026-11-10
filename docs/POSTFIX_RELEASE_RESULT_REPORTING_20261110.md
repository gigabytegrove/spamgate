# Native Postfix release helper: result reporting contract (2026-11-10)

The privileged helper invokes only `/usr/sbin/postsuper -H <queue-id>` after validating root privileges and a single alphanumeric queue ID. This change hardens the **result reporting** boundary: a successful subprocess with no output sink now fails closed; a failed write to the sink propagates as an error; subprocess failures still take precedence and never emit a success record.

This is deliberately **not** evidence of delivery or successful hold release on a live mail host. Postfix exit zero, output capture, and operator-visible reporting are distinct from queue-state verification. Host qualification must check the queue state before and after release, mail logs, Dovecot delivery/hold behavior, idempotency, and end-to-end disposition.

The helper still does not modify Postfix configuration automatically. Native launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, persistent `/opt/spamgate/data`, and Milter ports 38470/38472 remain unchanged.

Verification: three subprocess regression tests added. They require Linux and are exercised by the existing `go test -count=1 ./...` engineering workflow. No production host qualification is implied.
