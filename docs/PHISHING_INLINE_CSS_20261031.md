# Phishing inline-CSS visibility hardening — 2026-10-31

## Scope and failure

The phishing visible-link classifier previously searched for the literal substrings `display:none` and `visibility:hidden` anywhere inside an inline style attribute. That misclassified unrelated strings/custom properties as hidden and failed to respect later valid declarations and `!important` priority. This affected classifier evidence and could suppress real link-impersonation findings. The convenience wrapper also supplied a nil coverage pointer, which could panic on malformed HTML or inspection limits.

## Implementation

- Parse bounded inline declarations, excluding comments, quoted semicolons and function values.
- Match only literal supported display and visibility property values; preserve last-declaration and important precedence.
- Integrate into the existing visibility filter without changing scanner score weights, MIME budgets or mail dispositions.
- Normalize a nil optional coverage pointer before inspecting HTML.
- Add unit and full link-finding integration tests for hidden/visible cascades, deceptive CSS substrings, malformed HTML and anchor budget.

## Evidence and limitations

The parser is intentionally not a full browser CSS engine. External stylesheets, class selectors, media queries, CSS custom property substitution, inherited visibility overrides, escaped identifiers, and layout/opacity tricks are not resolved. It does not prove phishing precision/recall on independently labeled mail. No mail server configuration or running host is changed by this source commit.

Acceptance for issue #5 still requires independently labeled clean/spam corpora, measured false-positive bounds, and real-host qualification. This work is regression hardening, not beta signoff.
