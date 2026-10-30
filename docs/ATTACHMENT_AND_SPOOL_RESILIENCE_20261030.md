# SpamGate attachment evidence and unpublished spool recovery — 2026-10-30

## Scope and unchanged architecture

This pass preserves the native foreground launcher `/opt/spamgate/spamgate`, native worker `/opt/spamgate/spamgate-worker`, persistent data `/opt/spamgate/data`, and Postfix Milter ports 38470/38472. No mail-host configuration or `milter_default_action = accept` was changed. Neither feature silently rejects mail.

## MIME filename evidence (issue #5)

The MIME attachment inspector now emits explicit findings for executable/script/macro-enabled filename suffixes, deceptive document/media double extensions, bidirectional filename controls, and ambiguous trailing dots/whitespace. These findings are added independently of executable magic-byte and ZIP inspection. Office macro-enabled files receive a lower filename-only weight than direct executables. The scanner preserves existing `RISKY_ATTACHMENT` and `DOUBLE_EXTENSION` policy symbols, using default filename-only weights of +4 for executable/script suffixes, +2 for Office macros and +4 for deceptive double extensions. The MIME inspector records ordinary filename evidence at zero additional weight to prevent duplicate scoring; filenames found only inside forwarded RFC822 messages can still contribute a bounded score. The MIME parser still enforces the existing bounded message, part, recursion and byte limits.

Filenames are untrusted: operational labels strip line breaks, control characters and bidirectional overrides and are bounded to 120 UTF-8 bytes. Findings use category descriptions rather than leaking the entire hostile filename. Existing attachment signatures remain separately visible.

**Not qualified:** A dangerous extension is not proof of malware. No measured clean/spam corpus, precision/recall, independent AV comparison, ZIP-bomb corpus or production false-positive threshold has been certified. Review score/action thresholds before enforcing reject or hold.

## Durable SMTP spool recovery (issues #2 and #6)

The native SMTP relay spool writes temporary `.pending-*` records and publishes them atomically to canonical `<id>.json` jobs. A crash between temporary-file sync and publication can leave unpublished data. Earlier queue inventory ignored these files, which made a directory containing uninvestigated original-message bytes appear clean.

Now:

1. Inventory counts regular `.pending-*` files and their bytes without interpreting them as deliverable jobs.
2. Symlinked, nonregular and oversized unpublished files make inventory fail rather than being silently followed or discarded.
3. Startup emits a warning when retained unpublished files exist.
4. The authenticated SMTP queue API includes `pending_temps` and `pending_temp_bytes`. The browser queue page shows an operator warning.
5. Five-minute operations samples persist those counts and raise a critical `queue_unpublished_spool` alert, resolving it only after a clean inventory.
6. No automatic recovery, relay, deletion or reclassification of an unpublished file occurs. Its SMTP acceptance status is **unknown**. It may be a never-acknowledged intake or an interrupted state update for an existing canonical job.

This is specifically for the optional SpamGate SMTP intake/relay. **Postfix Milter mode uses Postfix's own queue**, not this outbox. Milter fail-open behavior is not altered.

## Read-only host investigation

With the administrator's knowledge, inspect `/opt/spamgate/data/delivery-queue` and correlate any `.pending-*` file timestamp with application/SMTP logs, canonical job IDs and remote relay responses. Do not blindly rename a temp file to `.json` or resend it; doing so can duplicate mail or deliver an unaccepted original. Preserve a forensic copy before any cleanup.

The browser shows counts, not message contents. Metrics history retains aggregate evidence only.

## Automated checks added

- Risky and benign filename cases, MIME integration and independent magic-byte scoring.
- Filename CR/LF and Unicode bidi sanitization.
- Unpublished spool file persistence through restart and normal queue processing.
- Symlinked and oversized temporary file rejection.
- Critical operations alert persistence and resolution.

## Beta blockers still open

The nine production-gate issues remain outstanding. Specifically: independent Postfix/Dovecot mailbox and hold evidence; full disk-full/crash matrix; SMTP/ARC/SPF/DKIM/DMARC conformance; measured false-positive bounds; tenant policy conflict lifecycle; browser/keyboard acceptance; cold restore; supported native update/rollback. Passing GitHub CI is not a production-host test.
