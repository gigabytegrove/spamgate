# Native SMTP HELO/EHLO extension-negotiation boundary — 2026-11-23

## Defect and correction

The trusted SMTP listener previously accepted XFORWARD identity attributes and MAIL FROM ESMTP options after basic HELO. HELO does not negotiate ESMTP extensions; this made the listener's advertised capability contract inconsistent with its accepted command grammar.

The session now records whether its latest successful greeting was EHLO. A valid HELO explicitly disables ESMTP mode, including when it follows EHLO; a subsequent EHLO re-enables it. XFORWARD is only accepted after EHLO and before MAIL. MAIL FROM with SIZE or BODY extensions is rejected in basic SMTP mode, while a basic MAIL FROM without extensions remains supported. The EHLO advertisement now lists both ADDR and HELO XFORWARD attributes, which the implementation already parses.

## Regression coverage

- HELO basic MAIL FROM and null reverse-path
- HELO refusal of SIZE and BODY=8BITMIME
- EHLO acceptance of declared MAIL extensions
- XFORWARD refused after HELO, accepted after EHLO
- HELO after EHLO revokes extension authorization and resets envelope
- RCPT cannot proceed after refused MAIL
- TCP loopback exercise of greeting changes and SMTP response codes

## Qualification and operational limits

Source commits were published through the repository connector. No GitHub Actions or Actions APIs were used. Direct Git checkout from this execution environment failed DNS resolution for github.com. The available local Go toolchain is 1.23.2, below the repository's declared Go 1.27.4. An owner-controlled build host was not accessible. Compilation, full tests, independent SMTP interoperability, real Postfix/Dovecot delivery, and production qualification: **NOT EXECUTED**.

This change is limited to the native SMTP protocol boundary. It does not claim resolution of issues #1–#9, crash-safe delivery, mailbox disposition, classifier precision, backup/restore, or release readiness. No live services, mail configuration, deployed artifacts, or releases were modified.
