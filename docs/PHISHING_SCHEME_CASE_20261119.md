# Phishing URL scheme case regression — 2026-11-19

Issue #5. The URL standard treats HTTP and HTTPS schemes case-insensitively. The existing visible-link classifier used case-sensitive comparisons after `net/url.Parse`, which retains the input scheme spelling. As a result, uppercase or mixed-case HTTPS destinations could evade mismatched-visible-host detection.

This change accepts HTTP(S) schemes using `strings.EqualFold` while keeping the existing bounded MIME traversal, organization matching, and zero-score incomplete-inspection policy. The new tests cover malicious mismatches and legitimate same-host/same-organization controls. No classifier thresholds, mail disposition, or live host configuration changed.

Qualification: code and tests committed; full repository Go tests, CI, clean/spam corpus precision/recall and live Postfix/Dovecot acceptance must be independently verified. Issue #5 remains open.
