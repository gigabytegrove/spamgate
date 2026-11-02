# Phishing rendered-link precision: zero opacity and HTML raw text — 2026-11-02

Production gate: #5 classifier breadth, evidence quality and false-positive safety.

## Defect and targeted behavior

Visible-link impersonation previously treated anchors written inside HTML `xmp`, `iframe`, `noembed`, `noframes` and `plaintext` as rendered clickable links. Raw-text content is not parsed as nested anchors by a browser. This could score benign examples or HTML fallback markup as phishing. `plaintext` consumes the remainder of the document, including apparent closing tags.

The renderer now excludes those raw-text contexts. A well-formed closing raw-text tag resumes normal visible-anchor inspection; an unterminated raw-text section other than `plaintext` produces incomplete-coverage diagnostic evidence rather than a speculative score.

The inline CSS visibility check now also handles literal `opacity:0` (including decimal, scientific and percentage zero) and `content-visibility:hidden`. Both suppress descendants' visible text. Normal CSS declaration ordering and `!important` precedence apply. Nonzero opacity, later valid overrides and unknown expressions do not get mistaken for zero. No external stylesheets, browser JavaScript or remote resources are fetched.

## Regression scope

New tests cover zero-opacity ancestors, cascade overrides, content-visibility, raw-text elements, plaintext-to-EOF, visible siblings and existing hidden/visible link controls. The scan remains opt-in; incomplete inspection is a zero-score diagnostic, not an automatic SMTP block.

This is a conservative static HTML subset, not a browser renderer. External CSS, media queries, advanced layout, and assistive-technology visibility are not fully modeled. Representative independently adjudicated ham/spam corpora and real-world false-positive measurements remain required; this change does not qualify gate #5 or the long-term beta.

The native launcher, worker, data root and Milter ports 38470/38472 are unchanged. No Docker substitution or live mail-host change is involved.
