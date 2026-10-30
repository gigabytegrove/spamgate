# Visible-link phishing precision — October 30, 2026

The opt-in HTML visible-link detector now extracts actual `href` attributes
rather than matching the substring `href` inside `data-href`, `title`, or
other attribute values. The first duplicate attribute is authoritative.
Quoted `>` characters are supported, and HTML comments are ignored.
Scheme-relative `//host/path` links are normalized to HTTPS for hostname
comparison. Oversized MIME parts are skipped instead of silently scoring a
truncated fragment. No network fetch or redirect following is performed.

Deterministic regressions cover positive mismatches and benign anchors,
plus scan-level opt-in behavior. These tests do not measure production
precision/recall; independently labelled corpora remain mandatory for #5.
