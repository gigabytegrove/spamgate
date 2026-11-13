# SMTP AUTH duplicate warning regression — 2026-11-13

Previous main HEAD: `66ff1eb56422d4b2e1194adf196d9fa0ccee66d0`.

Engineering qualification run 43478813410 failed in `TestCapabilityWarningsDeterministic`: the test fixture still expected only `DUPLICATE_EXTENSION` when two AUTH advertisements were present, although the implementation deliberately also emits `DUPLICATE_AUTH_EXTENSION`. The isolated Postfix/Dovecot workflow 43478813673 completed successfully at that previous HEAD; it does not qualify production hosts.

This change updates the stale deterministic fixture and adds eight table-driven warning scenarios, covering standard and legacy AUTH syntax, case folding, repeated mechanisms, unrelated duplicate extensions, empty AUTH and EHLO identity handling. No runtime SMTP behavior, Postfix settings, data directory, Milter listener or privilege boundary is changed.

Verification boundary: source regression tests are committed; they require exact-HEAD CI confirmation. Production Postfix/Dovecot, durable delivery, classifier accuracy, tenant enforcement, UI acceptance, backup/restore and native update/rollback remain open. Never infer production readiness from isolated CI.
