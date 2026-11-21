# Native spool in-flight delivery ceiling — 2026-11-21

The read-only `spamgate-spool-audit` command accepts `-max-delivering=N` (nonnegative integer, default -1 disabled). The gate counts only signed, validated published records in state `delivering`. Exceeding the limit returns exit status 1, with `gate_passed=false` and a `delivering=COUNT exceeds max-delivering=N` failure reason in JSON. Invalid limits return status 2. Equality passes.

This is a **monitoring gate**, not a concurrency control or evidence of SMTP acceptance. Live audit scans are not atomic. A crash can leave a signed record in `delivering` even when remote delivery outcome is uncertain; the operator must reconcile rather than blindly replay. The separate `-max-delivering-age-seconds` gate identifies stale in-flight records. No mail-server configuration, spool files, or services are changed by this command.

Engineering evidence: CI for starting HEAD `73dc295cfdb090ced2f4ea333558e4b8ecb5b014` failed in `TestIntegrityGateFailures/clean` because a non-nil empty slice was compared with nil using `reflect.DeepEqual`. Fixed that test expectation in commit `10c1ea4a73c60f71843214391124d377b313049d`. The present feature requires fresh final-HEAD Go tests and Actions qualification; a passing previous HEAD is not sufficient. Real Postfix/Dovecot delivery and hold acceptance remains unverified.
