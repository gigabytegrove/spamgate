# Phishing HTML visibility and false-positive hardening — 2026-10-31

## Production gate

Issue #5 remains open. The opt-in phishing classifier previously matched anchor-shaped strings inside HTML comments, scripts, styles, templates, textarea, head and other non-rendered elements. It also treated hidden anchor text as visible, and could use a second href after a first boolean href. Those are incorrect browser-visible URL claims and can inflate scores for legitimate mail.

This change adds a bounded, quote-aware HTML visibility prepass before visible-link mismatch scoring. It suppresses non-rendered subtrees, hidden/inert/aria-hidden elements and inline display:none or visibility:hidden. It preserves visible sibling anchors. Raw-text script/style/textarea/title content is skipped until a matching closing element. Malformed or unterminated markup produces zero-score incomplete-coverage diagnostics rather than speculative phishing findings. The first href attribute wins, including a boolean empty href.

The classifier is still opt-in. No thresholds, actions, message retention, Milter settings, ports, service files or production mail host are changed.

## Verification and limitations

The new regression matrix covers visible links, nested hidden elements, quoted greater-than signs, comments, raw-text elements, duplicate href, visible siblings, malformed input, and MIME coverage propagation. An isolated Go 1.23.2 harness passed 23 visibility-parser cases before repository integration; this is not a full application build. Exact-commit CI results must be recorded separately.

This is not a browser renderer or CSS cascade. External stylesheets, class-based hiding, conditional email-client markup, malformed browser tree-repair, Unicode URL confusables, redirects and URL reputation are not fully modeled. Do not claim false-positive rate improvements without labeled corpora and independent browser/corpus evidence. Real mail-host qualification remains outstanding.

Architecture unchanged: permanent /opt/spamgate/spamgate launcher, spamgate-worker, /opt/spamgate/data, HTTP 38470 and Milter 38472. No Docker substitution or live deployment.
