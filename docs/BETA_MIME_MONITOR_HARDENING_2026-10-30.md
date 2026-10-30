# SpamGate native long-term beta — MIME and monitor hardening (2026-10-30)

## Architecture invariant

This change does not replace the native foreground `/opt/spamgate/spamgate` launcher, the `spamgate-worker` child, the persistent `/opt/spamgate/data` directory, or Postfix Milter ports 38470 and 38472. No installer, production Postfix configuration, or live mail server is changed.

## Detection gate #5

- `InspectMIMEAttachments` now traverses `message/rfc822` forwarded-message wrappers (including base64-encoded wrappers) and inspects their nested MIME parts and attachment bytes.
- The inspector shares a 20 MiB decoded-part traversal budget across the entire MIME tree in addition to the existing 60-section, six-level, 5 MiB-per-part, and 20-finding limits.
- A multipart with additional parts beyond the 60-section budget emits `MIME_LIMIT` rather than silently treating the first 60 sections as complete inspection.
- The phishing-link MIME walker likewise traverses forwarded `message/rfc822` wrappers and now shares a 75-part budget across all nesting levels, rather than resetting the budget for every multipart layer.
- Unreadable forwarded content is reported as a zero-weight `MIME_MALFORMED`/`MIME_UNREADABLE` finding where the attachment inspector is enabled. A parser limit alone does not change the SMTP disposition or add a spam score.
- Regressions cover plain and base64 forwarded executables, forwarded deceptive links, benign forwarded links, malformed forwarded messages, and a multipart beyond the shared part limit.

**Remaining detection qualification:** A representative, independently labelled clean/spam corpus with documented false-positive bounds, feed failure policies, and real mail-host interoperability remains outstanding. These fixtures are engineering regressions, not proof of population-level classifier accuracy.

## Diagnostics gate #6

- Monitor history is checked with `Lstat` and a bounded 2 MiB reader before JSON decoding; a sparse/oversized history can no longer trigger an unbounded `os.ReadFile` allocation.
- The monitor refuses a symlink or device at `operations/monitor.json`, refuses a symlinked `operations` directory, and compares the opened file identity with the inspected path.
- Monitor writes retain same-directory temporary-file, sync, and atomic rename behavior. Existing corrupt/oversized/symlinked history is not replaced with an empty successful state.
- Regressions cover external symlink targets, symlinked operations directories, oversized sparse history, and ordinary restart persistence.

**Remaining diagnostics qualification:** Privileged host isolation, filesystem adversary races, real injected Postfix/Dovecot faults, alert delivery, and operational retention testing remain outstanding. No production-host tests were performed by these changes.

## Qualification policy

The exact final `main` commit must pass Go unit/race/vet, UI regression, native migration/update, Linux/Windows native compilation, and the isolated Postfix/Dovecot/Sieve workflow before this pass is considered CI-qualified. GitHub Actions is not a substitute for a supervised real-host install, delivery, recovery, or false-positive acceptance gate. All GitHub issues #1–#9 remain open until their complete acceptance criteria are independently met.
