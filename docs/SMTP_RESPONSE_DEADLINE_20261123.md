# SMTP response write deadlines — 2026-11-23

Scope: native SMTP listener only. No mail-host configuration or production service changes.

## Defect
The listener set a four-minute connection deadline once and a thirty-second command read deadline per command. It did not refresh the write deadline when sending replies. Consequently, a peer could receive a command timeout response only if the original write deadline had not expired, and a slow/nonreading peer could consume a listener slot while a reply blocked. The EHLO multiline response also bypassed the regular reply path.

## Change
All SMTP handler replies, including multiline EHLO, now use a single bounded response writer that refreshes a five-second write deadline independently of the read deadline. An expired read deadline does not prevent writing a terminal 421. EHLO write failures terminate the connection; other response errors are logged. The four-minute session limit still bounds command processing; only terminal response flushing may exceed that limit by up to five seconds.

## Verification
Source change and tests committed. Real owner-controlled Go build, full regression, native Postfix/Dovecot and mail-host tests NOT EXECUTED in this pass. No GitHub Actions used. Tests are not acceptance evidence until run on an approved builder.

## Remaining gates
Issues #1–#9 remain open. Durable queue crash/replay, actual Postfix/Dovecot disposition, classifier accuracy and false positives, tenant enforcement, diagnostics, browser workflows, backup/restore and native upgrade/rollback still require independent qualification.
