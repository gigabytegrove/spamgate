# SMTP enhanced reply evidence — 2026-11-20

Scope: issues #3 and #6. Record bounded RFC 3463-style enhanced reply codes from greeting, initial EHLO, STARTTLS, and post-TLS EHLO without retaining arbitrary server reply text. All lines in a multiline reply must agree, and the enhanced status class must match the three-digit SMTP reply class. Inconsistent or malformed advertisements are not presented as trusted evidence.

The diagnostic remains read-only and does not issue MAIL FROM, RCPT TO, DATA, BDAT or AUTH. This does not establish SMTP submission, Dovecot disposition, or real-host qualification. No Postfix, Dovecot, systemd or running mail-host configuration is modified.

Verification: source review and committed unit tests; no local full-repository execution because the checkout cannot resolve github.com. Final HEAD CI and production host evidence must be independently checked before acceptance. All nine production gates remain open.
