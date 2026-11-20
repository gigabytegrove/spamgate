# SMTP enhanced-reply control-byte boundary — 2026-11-20

## Scope
Issues #3 and #6. A manually constructed SMTP probe Result could previously pass enhanced-status evidence containing ASCII control bytes other than CR, LF, and NUL. The network reply parser already rejects these bytes, but the downstream evidence parser also handles synthetic or imported results and must enforce the same trust boundary.

## Change
The enhanced-status parser now rejects all C0 control bytes except HTAB, and DEL, anywhere in a reply line. HTAB remains permitted as an ASCII delimiter after the enhanced-status token. Numeric status validation, canonical classes, line/length limits, and the rule that no arbitrary server reply text enters findings are unchanged. This change is diagnostic-only and does not alter SMTP mail enforcement or running services.

## Regression coverage
The new test file exercises every representative C0 category and DEL in both token-adjacent and trailing positions, valid HTAB, Unicode whitespace rejection, canonical numeric classes, contradictory multiline replies, length limits, and manual Result evidence for all four SMTP stages.

## Verification boundaries
The source and tests were committed through the GitHub connector. Repository checkout in the local runner is blocked by DNS resolution of github.com; therefore no local full-module Go tests or builds are claimed. GitHub Actions must be inspected for the final commit separately. No real mail host was modified or qualified.

## Open gates
Issues #1–#9 remain open, including final delivery evidence, crash durability, SMTP/auth interoperability, classifier false-positive measurement, tenant policy, complete UI, production backup/restore and native rollback. The October 31 target has passed and beta qualification is not established.
