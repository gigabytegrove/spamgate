# SMTP enhanced status code capability evidence — 2026-11-19

This change extends read-only EHLO inspection to RFC 2034 ENHANCEDSTATUSCODES. It records unambiguous advertisements, detects duplicate or parameterized advertisements, and observes changes after a verified STARTTLS handshake. The initial EHLO identity line is never interpreted as an extension. No mail transaction, authentication, configuration mutation, or delivery is attempted.

## Qualification boundaries

The advertisement alone does not demonstrate that actual SMTP replies contain RFC 3463 enhanced status codes or that Postfix/Dovecot disposition is correct. Integration and live-host evidence remain required. Issues #1–#9 remain open; no long-term beta claim is made. The native launcher, worker, persistent data path and Milter ports remain unchanged.

Regression cases cover normal and lowercase advertisements, duplicate and malformed extensions, EHLO identity boundary, unknown keywords, post-TLS change, and ambiguous change suppression.
