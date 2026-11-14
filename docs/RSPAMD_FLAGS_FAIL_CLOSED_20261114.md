# Rspamd compatibility flags: fail closed — 2026-11-14

The HTTP scan handler previously accepted `pass_all` and `groups` but never implemented their requested semantics. In particular, silently ignoring `pass_all` could cause a client to receive a reject or quarantine decision when it explicitly requested a different behavior. The worker now returns HTTP 422 for unsupported flags rather than falsely advertising compatibility.

Supported flags remain `no_log` (skips scan history persistence) and `milter` (existing compatibility behavior). Unknown, duplicate and empty comma-separated flags are rejected. Absent Flags remains valid. No changes to the native launcher, persistent data path, Milter listeners or production mail-server configuration.

Isolated Go parser tests and vet were executed successfully; full repository CI, Postfix/Dovecot interoperability and production-host acceptance require independent evidence. This is not beta qualification.
