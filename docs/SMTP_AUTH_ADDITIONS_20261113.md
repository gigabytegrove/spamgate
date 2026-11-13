# SMTP AUTH capability additions after verified STARTTLS — 2026-11-13

The read-only SMTP probe now reports `AUTH_MECHANISMS_ADDED_AFTER_TLS` when at least one mechanism appears after a verified TLS handshake and successful post-TLS EHLO while at least one mechanism was advertised before TLS. The existing removal finding is retained, so mixed additions/removals produce both findings. Mechanism names are normalized case-insensitively and are not copied into diagnostic messages.

This does not authenticate, submit credentials, send a message, change Postfix or Dovecot configuration, or prove production SMTP compliance. Missing/rejected EHLO and unverified TLS cannot support the finding. Eleven regression cases cover additions, removals, mixed changes, normalization and evidence gates.

Qualification requires execution of Go tests, isolated Postfix/Dovecot CI, and independent host acceptance; no production qualification is implied by this source change.
