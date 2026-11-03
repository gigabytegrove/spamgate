# Classifier ARIA regression reconciliation — 2026-11-02

## Incident

Engineering qualification for commit `633e4f313d21254c2056570e7396a5711d6ae034` failed in the Go unit-test step of run 41569766336. `TestPhishingEncodedAriaHidden` asserted that an encoded `aria-hidden="true"` ancestor must suppress a visible-link phishing finding. That assertion contradicted the newer, correct production behavior and the dedicated ARIA tests: ARIA removes content from the accessibility tree, but does not itself prevent visual rendering or pointer interaction.

## Correction

The existing regression now requires detection for encoded `aria-hidden` values, including mixed case, and requires suppression only where a separate actual visual hiding mechanism (`hidden` or `display:none`) applies. A visible sibling is also checked. The production classifier behavior is unchanged by this correction.

## Verification contract

Run `go test -count=1 ./internal/core -run 'TestPhishingEncodedAriaHidden|TestPhishingAriaHidden'`, then `go test -count=1 ./...`, `go test -race -p 1 -count=1 -timeout=15m ./...`, and `go vet ./...`. Verify the exact final HEAD in the engineering and disposable Postfix/Dovecot integration workflows; do not treat an older green run as evidence for this commit.

This regression correction is not evidence of representative phishing precision/recall or of production mail-host qualification. Production gates #1–#9 remain open until their independent acceptance evidence is complete.
