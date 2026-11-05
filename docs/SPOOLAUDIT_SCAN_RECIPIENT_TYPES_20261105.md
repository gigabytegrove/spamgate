# Native spool scan-recipient identity validation — 2026-11-05

## Root cause and correction

Go's `encoding/json` unmarshals a JSON `null` into a string without an error, leaving the empty string. The read-only native spool auditor previously unmarshaled the persisted `scan.recipients` array directly into `[]string`. A malformed `null` array member could therefore compare equal to an empty-string recipient in the durable original. The auditor now decodes the array as `[]json.RawMessage`, explicitly rejects null elements and non-string types, then compares the decoded string sequence against the durable original in order. An explicitly empty string remains distinguishable from JSON null; sender `""` remains valid for SMTP DSNs.

## Regression and scope

`internal/spoolaudit/scan_recipient_types_test.go` exercises 12 scenarios: single and ordered multiple recipients, null element, mixed null, number, boolean, object, null array, scalar array substitution, empty array, Unicode escape, and order mismatch. This is forensic validation only: it does not rewrite or replay queued originals and does not change live SMTP policy. The audit is still a bounded, read-only observation, not a transactional snapshot.

## Qualification evidence

Source and prior tests were inspected via the GitHub connector. Changes were committed directly to `main` and commit identifiers returned by GitHub. Local Go execution was unavailable in this run because the execution container could not start (SessionLimitReachedError). A GitHub workflow query on the intermediate test commit returned no pull-request-triggered workflow runs; a status query returned no statuses. Those empty responses do not establish absence of push-triggered CI. No passing regression, full CI, Postfix/Dovecot, or production mail-host qualification is claimed.

## Open gates

GitHub issues #1–#9 remain open: actual Postfix/Dovecot disposition and holds, durable crash/retry delivery, SMTP/authentication interoperability, tenant-policy enforcement, classifier accuracy and false positives, retained diagnostics, browser UI acceptance, backup/restore, and native update/rollback. Do not close them based on this forensic-only correction. Preserve the permanent foreground launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, data `/opt/spamgate/data`, Milter ports 38470/38472, and the requirement not to modify running mail servers automatically.
