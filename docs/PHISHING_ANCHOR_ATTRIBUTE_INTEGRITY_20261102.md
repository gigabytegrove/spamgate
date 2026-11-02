# Rendered HTML anchor-token integrity — 2026-11-02

Production gate #5 remains open. The earlier phishing classifier ran a regular expression over HTML that still contained quoted tag attributes. A literal `<a href=...>...</a>` inside `data-template`, `title`, or `aria-label` could be misclassified as a clickable, impersonating link.

The classifier now uses quote-aware tag boundaries and only opens a claim on an actual anchor tag. Visible text is accumulated only between anchor tokens; attribute values never become visible URL claims. A nested anchor closes the earlier claim instead of merging its text and destination. Text has a 4096-byte inspection limit, the existing 50-anchor and 10-finding caps remain, and truncated/unclosed claims produce zero-score coverage diagnostics.

Regression tests cover forged anchors in attributes, real adjacent anchors, quoted greater-than signs, HTML entities, nested anchors, MIME integration, long text, anchor budgets and raw-text suppression.

No SMTP policy, scoring weight, runtime default, Postfix configuration, or Dovecot configuration is changed. This parser is not a full browser DOM/CSS/JavaScript engine. Independent corpus-based false-positive measurement, external stylesheets, redirect analysis and real-mail-host qualification remain outstanding.
