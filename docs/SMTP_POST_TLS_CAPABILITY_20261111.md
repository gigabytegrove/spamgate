# Post-STARTTLS capability verification (2026-11-11)

The read-only SMTP probe now records `post_tls_starttls_advertised` in its JSON result and emits `STARTTLS_ADVERTISED_AFTER_TLS` only when the initial EHLO succeeded, TLS was cryptographically verified, and the second EHLO returned 250. RFC 3207 states that the STARTTLS extension MUST NOT be advertised after TLS negotiation.

This is a protocol observation, not a mail-host acceptance result. The probe never sends AUTH credentials, MAIL FROM, RCPT TO or DATA, and does not change Postfix/Dovecot settings. It does not establish actual submission, delivery, hold, tenant enforcement, spam-classification accuracy, restore safety or native rollback.

Regression coverage includes a repeated STARTTLS capability, normal post-TLS EHLO, unverified TLS, rejected post-TLS EHLO and rejected initial EHLO. End-to-end lab and production-host qualification are separate required gates.

Architecture remains: foreground `/opt/spamgate/spamgate`, `spamgate-worker`, persistent `/opt/spamgate/data`, Postfix Milter ports 38470/38472, native Linux deployment without Docker or automatic mail-server reconfiguration.
