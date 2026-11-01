# Native host-probe bounded subprocess capture (2026-11-01)

Production gates: #1, #3 and #6. This is diagnostic hardening, **not** production mail-host qualification.

The opt-in Postfix and Dovecot configuration checks previously used `subprocess.run(capture_output=True, timeout=5)` and checked output size only *after* the command returned. A broken, hostile or misconfigured `postconf`/`doveconf` executable could allocate unbounded memory during those five seconds. Forked descendants holding the stdout/stderr pipes open could also extend capture beyond the direct process's lifetime.

Both diagnostics now use the same POSIX-only bounded reader. It starts the exact executable and fixed argument vector (never a shell), closes stdin, starts a separate process group, incrementally drains stdout and stderr through nonblocking pipes, limits **each** to 65,536 bytes, enforces a five-second end-to-end deadline including inherited pipes, and kills the process group on failure. Errors are fixed diagnostic strings; raw stdout/stderr and secret configuration are not included in the report. Existing strict UTF-8, NUL, nonzero-exit and stderr refusal checks remain in place. No service configuration, SMTP message, queue or mailbox is modified.

Run the hermetic regressions:

```bash
python3 scripts/test-spamgate-bounded-command.py -v
python3 scripts/test-spamgate-postfix-config-probe.py -v
python3 scripts/test-spamgate-dovecot-config-probe.py -v
```

The first suite covers successful output, exit codes, exact byte limits, stdout/stderr floods, timeout, forked child pipe retention, unsafe argv, nonexistent executables and invalid UTF-8. The latter two suites include integration flood regressions. CI runs all three suites in engineering qualification. This is intentionally Linux/POSIX-only for native host inspection; it does not alter the Windows desktop executable.

Remaining gates include actual Postfix/Dovecot action enforcement and mailbox placement, ISPConfig/LMTP, durable crash and duplicate delivery, independently measured classifier false positives, tenant policy completeness, browser acceptance, and backup/upgrade/rollback on a real mail host. No running mail server is changed by this work.
