# SMTP SIZE evidence integrity — 2026-11-13

The read-only SMTP diagnostic now reports `SIZE_LIMIT_CHANGED_AFTER_TLS` only when both EHLO exchanges explicitly advertise SIZE, each supplies a known numeric limit, neither SIZE parser reports ambiguous or malformed evidence, STARTTLS is verified, and the post-TLS EHLO reply is 250.

Previously, contradictory synthetic or partially corrupted evidence could produce a numeric-drift finding even when the parser had flagged the advertised SIZE limit as untrustworthy. The independent `SMTP_SIZE_LIMIT_UNTRUSTWORTHY` finding is preserved.

Regression cases cover malformed and duplicate evidence on either side, missing advertisements, and unverified or rejected TLS/EHLO. This is diagnostic integrity work only: it does not submit mail, verify SMTP AUTH, change Postfix/Dovecot, or establish real-host compliance. Production issue #6 and the other open acceptance gates remain open.
