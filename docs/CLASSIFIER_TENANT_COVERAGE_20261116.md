# Explicit tenant coverage for offline classifier qualification

The evaluator supports `-expected-tenants=alpha,beta`. When supplied, this requires the corpus to contain exactly the named tenant set, rejecting missing tenants, unexpected tenants, duplicate option entries, and empty option entries before emitting a report. Tenant names in the option are whitespace-trimmed and compared case-sensitively; corpus values are unchanged.

This prevents accidentally excluding an entire weak-performing tenant from the supplied evaluation corpus. Operators must source the expected tenant inventory independently of the corpus being evaluated. Without the option, exploratory evaluation remains backward compatible.

This is **not** evidence of real-world classifier accuracy, independent labels, representative samples, actual Postfix/Dovecot disposition, durable delivery, SMTP authentication compliance, backup/restore, native rollback, or beta readiness. A full end-to-end mail-host qualification and regression suite remain mandatory.

No running mail server, native launcher, worker, persistent data location, or Milter port is changed.
