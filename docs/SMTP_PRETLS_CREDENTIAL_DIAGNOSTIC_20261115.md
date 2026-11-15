# SMTP pre-TLS credential mechanism diagnostic — 2026-11-15

The read-only SMTP diagnostic now emits `CLEARTEXT_CREDENTIAL_AUTH_ADVERTISED` when a trustworthy successful pre-TLS EHLO response advertises `PLAIN` or `LOGIN`. This is a warning to check server-side refusal of unencrypted credential submission, not proof that the server accepts such submissions. It deliberately does not issue AUTH commands or transmit credentials.

Malformed or duplicate AUTH advertisements are excluded from this specific finding because the existing `AUTH_EVIDENCE_UNTRUSTWORTHY` finding already identifies their ambiguity. AUTH mechanisms first advertised after a verified TLS handshake do not trigger the warning.

This change does not qualify actual SMTP submission, SASL login, Postfix policy, tenant enforcement, or production mail delivery. Those require an independently controlled live mail-host test.
