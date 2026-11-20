# Native backup path isolation — 2026-11-20

Scope: issue #8, cold backup verification and restore. The CLI now independently protects the permanent /opt/spamgate/data tree even when an operator supplies an alternate --active-data. It also rejects authentication keys stored within the backup, the active data directory, or the permanent data directory, including symlink aliases. Key and manifest must be distinct regular files.

No service, Postfix configuration, or Dovecot configuration is modified. The CLI still requires an authenticated immutable backup and a nonexistent cold restore target. This is defensive preflight, not a replacement for host qualification or filesystem race hardening.

Verification: new Go tests committed; complete GitHub Actions conclusions must be checked separately. Real mail-host restore and rollback remain unverified. Production gates #1–#9 remain open.
