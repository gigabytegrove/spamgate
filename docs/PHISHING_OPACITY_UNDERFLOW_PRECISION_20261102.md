# Native classifier opacity-underflow precision (2026-11-02)

## Defect

The inline CSS visibility filter parsed opacity literals using Go float64.
A nonzero literal such as `opacity:1e-999` underflows to numeric zero.
The previous classifier consequently discarded every anchor in the element
as invisible, even though the source explicitly expressed nonzero opacity.
This is a conservative detection-coverage fix, not a browser CSS conformance
claim.

## Correction

After numeric validation, if the parsed opacity is zero, inspect only the
mantissa (before any scientific-notation exponent). A nonzero decimal
mantissa means that precision was lost and the value is treated as unknown
rather than invisible. Genuine numeric zero, including `0e-999` and
`-0.0`, retains existing hidden semantics. Invalid and nonfinite numbers
remain unknown.

## Verification and outstanding gates

`go test ./internal/core -run TestPhishingOpacityUnderflowDoesNotSuppressLinks -count=1`
is the focused regression command. The test covers positive/negative
underflow, percentages, zero controls, and full visible-link integration.
This change does not establish classifier precision/recall on representative
mail, complete CSS/browser rendering conformance, or any production
Postfix/Dovecot qualification. All nine production gates remain open.
