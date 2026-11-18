# Independent classifier holdout qualification — 2026-11-18

## Scope
Issue #4 classifier false-positive/accuracy qualification and issue #5 tenant isolation. This change is an offline API only; it does not change live policy, Postfix, Dovecot, delivery, or the native launcher.

`QualifyIndependentHoldout` selects a threshold on the tuning corpus and freezes it before evaluating the independent holdout. It requires both corpora to be nonempty, disjoint sample IDs, identical tenant coverage, and passing per-tenant and overall false-positive, precision and recall statistical gates. No passing tuning candidate means no holdout candidate and no qualification. Missing and newly appearing tenants are reported deterministically.

## Evidence and limitations
Source and tests committed; CI completion and execution must be checked for the exact final commit. This API does not independently prove labels, time separation, message-family separation, representative traffic, operational classifier detection breadth, or production false-positive rates. A human-reviewed, independently labeled corpus and live-host end-to-end evidence remain mandatory.

## Locked deployment
Permanent foreground launcher: `/opt/spamgate/spamgate`; worker: `spamgate-worker`; persistent data: `/opt/spamgate/data`; Postfix Milter ports: 38470/38472. No Docker substitution, no automatic running mail-host changes.

## Remaining gates
Issues #1–#9 remain open until actual acceptance evidence closes each: Postfix/Dovecot holds and disposition, durable delivery, SMTP/auth compliance, classifier breadth/false positives, tenant policy enforcement, diagnostics, browser UI, backup/restore, and native update/rollback. The October 31, 2026 target has passed; beta is not qualified.
