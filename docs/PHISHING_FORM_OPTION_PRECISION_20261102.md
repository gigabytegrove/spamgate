# Native classifier: inert form-option markup

## Scope

HTML anchors embedded in `select`, `datalist`, `option` and `optgroup` content are not clickable email links. Treating these as browser-visible navigation targets can incorrectly produce `PHISHING_VISIBLE_LINK` evidence. The visibility filter now excludes these form-option subtrees before the quote-aware anchor tokenizer runs.

## Regression coverage

`go test ./internal/core -run 'TestPhishingFormOption' -count=1` covers inert options, nested groups, visible siblings and MIME integration. This change does not modify scoring thresholds, Postfix disposition, native launcher, persistent data paths, Milter ports or mail-server configuration.

## Qualification limits

This is a targeted false-positive correction, not a complete HTML5 browser parser. It does not establish representative corpus precision/recall or live ISPConfig qualification. No production mail host is modified by this change.
