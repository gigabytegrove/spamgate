# Browser-normalized numeric IPv4 phishing detection — 2026-11-19

Issue: #5. This change closes a narrow detection bypass, **not** the classifier accuracy or beta acceptance gate.

## Behavior

Browsers accept several numeric IPv4 host spellings that are not canonical dotted-decimal IP literals. Examples include `134744072`, `0x08080808`, `010.010.010.010`, `8.526344`, and `8.8.2056`, all representing `8.8.8.8`. A deceptive HTML anchor can therefore claim `https://bank.example.com/` while navigating to one of these alternate hosts.

The classifier now recognizes bounded 1–4 component decimal, hexadecimal, and octal numeric forms, normalizes them without DNS, and applies the existing public-IP and special-purpose exclusion policy. Private, loopback, documentation and CGNAT addresses do not become phishing evidence merely because they are encoded numerically. Invalid or overflowing forms are not promoted to IP evidence.

This deliberately avoids DNS resolution and changes neither SMTP policy nor disposition. It does not claim full WHATWG URL parser conformance, and browser normalization differences remain a regression concern.

## Verification evidence

The standalone Go parser and 20 boundary cases were executed successfully with the locally installed Go toolchain, independently of the repository. The repository-wide tests and final-commit GitHub Actions conclusions must be inspected separately; isolated tests are not equivalent to complete qualification.

No production Postfix, Dovecot, or ISPConfig configuration was touched. There is no live-mail-host evidence in this change.

## Outstanding production acceptance

Issues #1–#9 remain cumulative production gates: real hold/Junk disposition, durable delivery, SMTP/authentication behavior, independently measured classifier precision/recall and false-positive rate, tenant isolation, diagnostics, browser acceptance, native backup/restore, and update/rollback. Native launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, persistent `/opt/spamgate/data`, and Milter ports 38470/38472 are unchanged. No Docker replacement or automatic mail-server changes.
