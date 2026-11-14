# Rspamd SMTP path identity and recipient-budget hardening — 2026-11-14

The HTTP compatibility worker previously used broad angle-bracket trimming for From, Rcpt and Deliver-To. Nested or incomplete SMTP paths could be silently normalized into apparently valid identities. The request also allowed 100 Rcpt values plus an additional Deliver-To value, exceeding its documented 100-recipient budget.

This change removes only one complete path wrapper, rejects empty recipient identities, nested or mismatched angle brackets, comma-separated address lists and leading/trailing whitespace within a wrapper. It retains null reverse-path support for From and preserves quoted local-part content without rewriting it. The total Rcpt plus Deliver-To budget is 100.

Scope: request metadata validation only. This is not full RFC 5321/6531 mailbox grammar validation, classifier calibration, production Postfix qualification, or proof of durable mail delivery. The standalone helper regressions are not a substitute for exact-HEAD repository CI and live-host evidence. Native launcher, worker, data directory, Milter ports and running mail server are untouched.
