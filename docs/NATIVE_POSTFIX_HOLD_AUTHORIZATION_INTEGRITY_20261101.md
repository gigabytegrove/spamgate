# Native Postfix HOLD authorization integrity and real helper release — 2026-11-01

Scope: GitHub issue #9, with supporting coverage for #1 and #6. This is a disposable-host and unit-test qualification improvement, **not production mail-host acceptance**.

## Changes

- The read-only `postqueue -j` HOLD parser now rejects duplicate JSON keys (including case-folded and Unicode-escaped aliases), malformed UTF-8, trailing JSON, incomplete arrival/recipient evidence and negative message sizes. A failed inventory stops correlation and release rather than accepting ambiguous queue ownership. Ordinary Postfix optional fields and null reverse paths remain supported.
- Postfix queue inspection uses a one-second subprocess pipe wait limit in addition to the existing four-second execution deadline, so an inherited output pipe cannot block indefinitely.
- The disposable GitHub Actions host installs the existing narrow root-owned `postfix-hold-release` helper **before** the live SMTP/Milter tests. Both the LDA and LMTP runs release an actually held Postfix queue entry through `sudo -u spamgate sudo -n -- /usr/local/libexec/spamgate/postfix-hold-release <queue-id>`, never directly through root `postsuper` when the privilege-lab flag is enabled.
- The existing negative privilege tests still check broad `postsuper`, `ALL`, argument injection, and unprivileged direct invocation. A new 16-case adversarial inventory suite plus valid Postfix compatibility fixture run in the standard Go qualification workflow.

## Safety and evidence boundaries

The integration host is disposable GitHub Actions Ubuntu; no production Postfix configuration or service is changed. The helper's installation is **explicit in the disposable CI job only**. A successful `postsuper -H` means release was requested, not final delivery; the existing Dovecot LDA/LMTP mailbox identity and count checks remain mandatory. The browser HTTP release path and real production ISPConfig persistence are still unqualified. Postfix queue-ID reuse, multi-recipient tenant ownership, disk-full recovery, cold restore, independent authentication vectors and false-positive corpora remain open.

CI must be checked against the exact commit before recording a pass. Preserve `/opt/spamgate/spamgate`, `spamgate-worker`, `/opt/spamgate/data`, Milter ports 38470/38472, and native foreground execution.
