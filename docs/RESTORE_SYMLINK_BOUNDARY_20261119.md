# Restore target symlink boundary — 2026-11-19

## Defect and correction
The native `spamgate-backup-verify -operation restore` path guard previously compared `filepath.Abs(target)` with the canonical operator active-data directory. A restore destination beneath a symlink to the active directory could evade that lexical comparison, even when the destination itself did not exist. The command now resolves the nearest existing ancestor with `filepath.EvalSymlinks`, reconstructs nonexistent trailing components, and compares the resulting canonical destination against both the supplied active-data boundary and the permanent `/opt/spamgate/data` boundary.

## Changed files
- `cmd/spamgate-backup-verify/main.go`: canonical restore-target ancestor resolution and centralized permanent-data overlap check.
- `cmd/spamgate-backup-verify/restore_symlink_boundary_test.go`: alias to active directory, nested missing target, dangling symlink, and no-side-effect regressions.

## Evidence
- Source inspected on `main` at `c808836261744707a3f85ef54e6ef5594ea8c53f`.
- Commits `0dbc21dc63ab0256416cbe5cf474379bf77cf41d` and `9a234a3e615f27229d1aece805901394b032d051` were pushed and confirmed as branch HEAD.
- GitHub connector's commit workflow lookup returned no runs; it filters to PR-triggered runs and does not establish push CI status. Combined commit status lookup returned no statuses.
- Local GitHub checkout failed DNS resolution (`Could not resolve host: github.com`); new Go tests could not be run locally.
- No mail host was touched, and no real-host restore or production Postfix/Dovecot qualification is claimed.

## Outstanding
Canonicalization before publication is not a substitute for descriptor-relative, race-free destination creation: an adversary with write access to ancestor directories may change them after validation. Test actual restore invocation and native systemd integration, verify complete production backup/restore and update rollback, and qualify issues #1–#9 before beta. Preserve the locked native launcher, worker, data path, and Milter ports. No Docker substitution or live mail configuration changes.
