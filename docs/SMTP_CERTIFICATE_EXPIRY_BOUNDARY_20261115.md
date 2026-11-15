# SMTP certificate validity evidence — 2026-11-15

The read-only SMTP diagnostic reports the leaf certificate's remaining validity in whole days, rounded upward for positive fractional days. Expired certificates use -1; certificates expiring at the observation instant use 0. This avoids reporting a still-valid certificate with one hour remaining as zero days.

Assessment distinguishes TLS_CERTIFICATE_EXPIRED from TLS_CERTIFICATE_EXPIRING (0–14 days), with no duplicate finding. The reported TLS certificate is only populated after successful verification of a STARTTLS handshake. In normal operation an expired certificate should cause handshake verification failure instead of producing a certificate expiry finding; the expired-result branch is defensive against inconsistent or synthetic diagnostic records.

This is not SMTP AUTH compliance, mail-host qualification, production TLS deployment validation, or proof of reliable mail delivery. Real-host and cross-version evidence remain required under issues #1–#9. No mail-server configuration or runtime process was modified.
