# Offline validation of durable relay originals

The native relay now validates the persisted envelope, SMTP DATA framing and RFC 5322 header encoding before dialing the upstream server. Invalid persisted originals return `invalidRelayOriginalError` and are eligible for dead-letter handling even if the upstream relay is unavailable. A well-formed original still gets a retryable network failure. This does not change the accepted original, the Milter listeners, native launcher, persistent spool or host mail configuration.

Evidence required before issue #2 closure: exact-HEAD Go regression and race tests, fault-injected durable queue lifecycle, real Postfix/Dovecot disposition, power-loss and disk-full tests, duplicate-acknowledgment qualification, and production-host evidence. No such production evidence is asserted here.
