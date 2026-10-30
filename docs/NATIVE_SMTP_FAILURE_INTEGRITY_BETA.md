# Native SMTP failure integrity — October 30, 2026

The native SMTP ingress now distinguishes malformed RFC 5322 originals (550)
from scanner infrastructure faults (451, retryable). In particular, an
unavailable ClamAV service cannot silently cause permanent rejection of a
legitimate original. Failed quarantine persistence also resets the SMTP
transaction rather than leaving old recipients eligible for another DATA.
The direct-relay fallback likewise clears the envelope after DATA.

This does not change Postfix's milter_default_action=accept, the native
launcher/worker topology, persistent data path, or Milter port assignments.
A 451 means the sender is responsible for retry; it is not proof that a
particular sender actually retried or that final delivery occurred.

Remaining: real Postfix/Dovecot placement, power-loss fault injection,
queue retry/duplicate matrix, classifier corpus, tenant policy, browser
acceptance, and native upgrade/rollback qualification.
