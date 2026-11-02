# Native Postfix HOLD envelope identity and required inventory evidence — 2026-11-01

Production gates: #1 (HOLD and privilege), #6 (read-only diagnostics), #9 (real Postfix disposition).

## Security defect and fix

Previous HOLD correlation applied Unicode-aware case folding to the **entire** SMTP mailbox and stripped any number of angle brackets from senders. SMTP local parts are not guaranteed to be case-insensitive. As a result, a queue entry for `user@example.org` could inherit an earlier SpamGate HOLD scan for `User@example.org`, including a different multi-recipient multiset. A malformed nested sender could also be treated as a legitimate one. A privileged release must not be authorized from that ambiguous identity.

The new comparison preserves each local part byte-for-byte, folds only an ASCII domain, accepts an exact optional sender angle pair and the standard null reverse path, and rejects malformed/ambiguous addresses. It counts each recipient occurrence separately and requires complete sender, queue, arrival, and recipient evidence. Postfix HOLD JSON now must explicitly contain sender, queue ID, arrival time, message size and recipients; absent or null fields fail closed. Existing queue-ID uniqueness, timestamp window, complete recipient count, advisory lock, CSRF, durable pre-command audit, and narrow root helper remain in place.

Conservative limitation: SMTPUTF8 local parts compare byte-for-byte; internationalized domains must be pre-normalized to ASCII A-labels. Quoted local parts containing whitespace or embedded `@` are intentionally not eligible for automatic privileged release. These messages require manual host review; this is safer than guessing an identity. Some MTAs intentionally fold local parts during address rewriting; such configurations may now refuse correlation and need independent qualification. Do not weaken comparison to recover convenience.

## Verification scope

Isolated Go identity tests and stubbed correlation/race checks were run before the push. Repository-wide Go unit/race tests, vet, browser regressions, and disposable Postfix/Dovecot integration must be inspected at the **exact pushed commit**; no claim of production-host qualification follows from those tests. The HTTP regression uses an injected inventory and command; it proves the authorization decision and audit behavior, not a real postsuper invocation.

Locked architecture: `/opt/spamgate/spamgate` foreground launcher, `spamgate-worker`, persistent `/opt/spamgate/data`, Milter ports `38470/38472`. No Docker substitution or automatic mail-server configuration changes. October 31 deadline has passed; the nine cumulative production gates remain open until independently qualified.
