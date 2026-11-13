# SMTP greeting rejection evidence — 2026-11-13

Production gate: #6 (actionable SMTP diagnostics), with #3 protocol conformance still open.

## Observed defect
The SMTP assessment returned no finding when the server returned a non-220 greeting and no EHLO reply. This made a refused greeting (for example SMTP 421 service unavailable or 554 service refused) indistinguishable from a probe that had not obtained any greeting evidence. The diagnostic did not submit credentials or mail.

## Correction
`SMTP_GREETING_NOT_ACCEPTED` is a warning when a numeric SMTP greeting is present but differs from 220. A missing greeting code (0) is not invented as a server refusal. The finding is emitted before the EHLO gate, so a rejected greeting remains visible even when no EHLO occurred. Existing EHLO, STARTTLS and AUTH evidence gates remain in place.

## Regression coverage
Six table-driven cases cover 421, 554, 250, 220, missing greeting and contradictory EHLO evidence. An additional test confirms a refused greeting with no EHLO does not invent STARTTLS or authentication-policy findings.

## Qualification boundaries
This is source and regression coverage, not proof of a real mail-host failure or acceptance. Exact-HEAD Go tests, CI, DNS failures, socket-level transport behavior and real Postfix/Dovecot acceptance must be checked independently. No production host, systemd unit, Postfix configuration, Dovecot configuration or native update mechanism was changed.

## Remaining gates
Issues #1–#9 remain open: end-to-end mail disposition, durable delivery, authentication conformance, tenant policies, classifier calibration, retained diagnostics, browser acceptance, native backup/update/rollback and privileged hold/Junk workflows. The October 31 target has passed; beta qualification is not claimed.
