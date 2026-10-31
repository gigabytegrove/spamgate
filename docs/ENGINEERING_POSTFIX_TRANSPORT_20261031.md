# Native SpamGate Postfix transport evidence engineering — 2026-10-31

## Scope and code evidence

Baseline inspected: eb9b7deda0fd71e3c93d59b91e2879efd4be8b0e on main, plus issues #1–#9 and the existing corpus qualification runner, its tests, native build script, and engineering workflow.

Added scripts/spamgate-postfix-evidence.py and scripts/test-spamgate-postfix-evidence.py. The new read-only analyzer consumes the durable SMTP corpus submission report and operator-exported Postfix logs, correlating the per-run unique Message-ID with the Postfix cleanup queue ID, matching recipient transport status, and queue removal. It writes a mode-0600 fsynced JSON report with a strict no-overwrite policy. Input bounds: 1–1,000 corpus cases, 1–16 log files, 64 MiB per file, 64 KiB per line. No SMTP connections or configuration writes are made.

Fail-closed cases include: missing cleanup, mismatched recipient, bounced/deferred/held queue, sent without observed removal, duplicate sent events, reused queue IDs, two queue IDs for one run, incomplete/failed submission journals, oversized lines, symlink log inputs, and existing output. An exit code of zero only certifies *Postfix transport correlation* for this observed log window. It does not certify mailbox placement, classifier action, SMTP AUTH, DKIM/SPF/DMARC, or delivery exactly once. A duplicate log export may cause conservative duplicate-event refusal.

Integration: engineering GitHub Actions workflow and scripts/build-github-assets.sh now run the new isolated regression file directly (hyphenated test filename, no unittest discovery).

## Verification performed

- Locally executed the isolated synthetic Postfix log test suite using Python 3: **20 tests passed** (the local working copy).
- Locally compiled both new Python modules with py_compile before the final extra tests.
- GitHub accepted the source, test, CI, native builder, and documentation commits on main; the exact final commit is recorded in Git history.
- The available GitHub connector exposes only PR-triggered commit workflow runs and legacy commit statuses. Neither yielded a verifiable final push-triggered Actions run at the time of this report. **GitHub CI result: unverified, not passed by assertion.**
- No production-host mail logs, Postfix/Dovecot runtime, mailbox contents, or native installer/rollback were accessed. **Real-host end-to-end qualification: not performed.**

## Production gate status (all remain open)

| Issue | State after this pass |
| --- | --- |
| #1 Postfix/Dovecot disposition | Added strict Postfix transport evidence; final Dovecot INBOX/Junk, hold/release and real host acceptance still missing |
| #2 Durable delivery | Existing spool work unchanged; crash/power-loss and full disk matrix still missing |
| #3 SMTP/auth compliance | Existing work unchanged; third-party conformance and ARC/SPF/DKIM/DMARC vectors missing |
| #4 Tenant policy | Existing work unchanged; live multi-recipient conflict qualification missing |
| #5 Classifier accuracy | Existing independent corpus harness unchanged; representative adjudicated corpus and measured confidence gates missing |
| #6 Diagnostics | Added durable bounded read-only queue-to-recipient evidence output; alerting and live correlation still missing |
| #7 Browser UI | Existing UI unchanged; browser and assistive technology acceptance missing |
| #8 Native update/rollback | Existing launcher and worker unchanged; real host update/rollback still missing |
| #9 Hold/Junk helper | Existing helper and Sieve integration unchanged; real privilege and mailbox placement qualification missing |

## Locked deployment contract

Do not replace /opt/spamgate/spamgate (permanent foreground launcher) with a worker binary. Do not remove /opt/spamgate/data. Preserve 38470/38472 and the user's Postfix milter_default_action=accept. No Docker substitution or automatic live mail-host changes.

**Decision:** Not qualified for long-term beta. The October 31 target does not supersede the real-host and regression gates.
