# Native recovery restore-target validation — 2026-11-10

## Defect and correction

The snapshot subcommand validated the raw `--target` argument with `validate_operator_path`, but the restore subcommand instead called `Path(args.target).absolute()`. On POSIX this may normalize a literal `.` path component before validation and did not check the complete target ancestry for symlinks. Consequently the documented fail-closed operator path policy was not applied symmetrically.

Restore now invokes `validate_operator_path(args.target)` before any restore operation. This rejects lexical `.` and `..` components and symlinked ancestors, including a missing final destination with an existing symlinked parent. Snapshot and verify retain their existing validation.

Three CLI regression tests assert refusal and no publication for a restore destination containing `..`, a restore destination containing `.`, and a restore destination beneath a symlinked parent. The tests also check the diagnostic reason, rather than merely any nonzero exit.

## Qualification and limitations

This change does not make online snapshots safe. Stop SpamGate before snapshot or restore and explicitly acknowledge offline mode. No mail server or service is stopped or reconfigured by this utility. There is no proof of real-host database consistency, ownership/ACL restoration, concurrent rename resistance, or cold disaster recovery. Path checking is not an atomic openat2-based confinement mechanism; another actor able to mutate ancestor directories can race the check. Do not deploy as a fully qualified recovery mechanism until independent real-host evidence exists.

The engineering qualification workflow already invokes `python3 scripts/test-spamgate-offline-data.py -v` on main pushes. Test source committed does not imply passing execution; inspect exact-HEAD CI before making such a claim.

## Locked deployment architecture

The permanent foreground launcher remains `/opt/spamgate/spamgate`, the worker remains `spamgate-worker`, persistent data remains `/opt/spamgate/data`, and Postfix Milter ports remain 38470 and 38472. No Docker substitution or automatic mail-host configuration changes.
