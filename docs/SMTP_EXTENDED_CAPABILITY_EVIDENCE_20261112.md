# Extended SMTP EHLO capability evidence (2026-11-12)

The read-only relay diagnostic now reports DSN (RFC 3461), CHUNKING and BINARYMIME (RFC 3030), REQUIRETLS (RFC 8689), and ENHANCEDSTATUSCODES (RFC 2034), in addition to SMTPUTF8, 8BITMIME, PIPELINING, SIZE, STARTTLS and AUTH.

All booleans describe **advertised extensions on the last successful EHLO**, not verified protocol transaction support. For required STARTTLS, the final EHLO is after certificate-verified TLS negotiation; pre-TLS capabilities are not carried forward. The probe never sends AUTH, MAIL FROM, RCPT TO, DATA, or BDAT. This is not evidence of successful mail delivery or Postfix/Dovecot disposition. In plaintext mode, AUTH is not attempted.

Tests: `TestRelayExtendedCapabilityEvidence` uses an isolated local SMTP listener, checks the parsed evidence and verifies that only EHLO and QUIT are sent. `TestRelayExtensionIdentityAndMalformedTokens` checks the EHLO identity boundary and malformed keyword rejection.

Production gate #3 remains open pending actual authenticated transaction, SMTPUTF8/8BITMIME/DSN/CHUNKING interoperability, STARTTLS trust-chain and real-host evidence. Gate #6 remains open pending complete operational diagnostics acceptance. No running mail server configuration was changed.

Locked native deployment remains `/opt/spamgate/spamgate`, worker `spamgate-worker`, persistent `/opt/spamgate/data`, Milter ports 38470/38472. No Docker substitution.
