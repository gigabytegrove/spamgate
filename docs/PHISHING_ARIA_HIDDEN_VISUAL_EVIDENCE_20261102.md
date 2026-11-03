# Rendered phishing links and aria-hidden — 2026-11-02

## Defect and impact

The HTML visibility prefilter treated `aria-hidden="true"` as if it were `hidden` or `display:none`. That is incorrect: aria-hidden removes content from the accessibility tree, but does not hide the content visually or prevent pointer interaction. An attacker could set aria-hidden on a visible misleading anchor and evade the visible-link mismatch classifier. This is a false-negative defect in gate #5.

## Correction

`phishingHiddenAttributes` no longer treats aria-hidden as visual suppression. HTML hidden, inert, and recognized inline CSS display/visibility/opacity suppression remain unchanged. The behavior is scoped to the existing HTML phishing prefilter; no enforcement thresholds, Postfix configuration, or runtime deployment settings are changed.

## Regressions

`go test ./internal/core -run 'TestPhishing(AriaHidden|Visibility)' -count=1`

Cases include aria-hidden on anchors and ancestors, mixed case, encoded attribute value, adjacent links, actual hidden and display:none overrides, inert controls, nested hidden children, and a MIME integration path.

## Qualification limitations

Tests demonstrate classifier behavior in controlled fixtures only. This does not establish representative precision/recall, browser-rendering equivalence for external CSS, real-mail-host performance, or production ISPConfig integration. Gate #5 and the other eight production gates remain open.
