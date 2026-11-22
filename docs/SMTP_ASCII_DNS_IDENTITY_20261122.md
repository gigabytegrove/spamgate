# SMTP recipient domain identity correction — 2026-11-22

Starting HEAD: 9380bed5a4125663daaa9346e2971d76daa2b656.

The existing `strings.EqualFold` comparison applied Unicode case folding to recipient domains. Unicode simple folding equates U+212A (Kelvin sign) and ASCII k; this is not a safe identity rule for an uncanonicalized SMTP envelope. The corrected comparison folds ASCII A-Z only, preserves local-part bytes and original wire address, and never mutates historical recipients. New regression asserts the Unicode collision is not deduplicated and ordinary ASCII domain case still is.

This is an incremental SMTP protocol correction, not full delivery, mailbox, tenant or beta acceptance. The production gates in issues #1–#9 remain open. No running mail server was changed; native launcher /opt/spamgate/spamgate, spamgate-worker, persistent /opt/spamgate/data and Postfix Milter ports 38470/38472 remain unchanged. The October 31 target has passed. Compilation, GitHub Actions and live mail-host qualification must be recorded separately and not inferred from commit publication.
