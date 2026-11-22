# SMTP recipient authorization: local-part boundary (2026-11-22)

Scope: issues #1 and #3. This change makes recipient-domain authorization independently reject malformed local-part control bytes, path delimiters and local parts longer than 64 octets, even if an internal caller bypasses the SMTP envelope parser. It does not rewrite recipient identities. Existing allowed ASCII domain comparisons remain unchanged.

## Contract

- An empty local part, a local part over 64 bytes, C0 control bytes, DEL, or angle brackets is rejected before checking the domain allowlist.
- Ordinary mixed-case local parts, plus tags and quoted local parts remain unmodified at this authorization boundary.
- Authorization is defense in depth. The actual SMTP command parser remains authoritative for syntax, SMTPUTF8, quoted-string handling and address acceptance.
- No change to queue persistence, Postfix/Dovecot configuration, listener ports, launcher, or running mail services.

## Verification / limitations

Source commits and committed test cases can be verified on GitHub. Complete Go compilation, full regression execution, native Linux integration, actual Postfix/Dovecot delivery, crash recovery, and mail-host qualification were NOT EXECUTED in this pass: the available local runtime cannot resolve github.com and is not the designated owner-controlled builder. GitHub Actions are prohibited and were not used.

This is an incremental security correction, not completion of issues #1-#9 or beta qualification. P0 durable queue lifecycle and real Postfix/Dovecot disposition remain outstanding, as do classifier false positives, tenant policies, diagnostics, browser workflows, cold restore and native update/rollback. Do not deploy or release on the strength of these source commits alone.
