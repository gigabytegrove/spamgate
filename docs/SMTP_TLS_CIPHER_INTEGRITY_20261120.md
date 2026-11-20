# SMTP TLS negotiation evidence integrity — 2026-11-20

## Scope
This change is read-only SMTP diagnostic work for production gates #3 and #6. It does not alter mail routing, Milter enforcement, the foreground launcher, worker, persistent storage, or Postfix configuration.

## Behavior
* Retain existing verification-chain, missing-cipher, unknown-suite, and unexpected client-certificate evidence.
* Classify cipher suites using the Go standard library's secure/insecure suite inventory rather than only a small name-substring list. Retain CBC detection for legacy suites.
* Report `TLS_VERSION_CIPHER_MISMATCH` when a recorded TLS 1.3 negotiation names a pre-1.3 cipher suite, or a recorded TLS 1.2 negotiation names a TLS 1.3 suite.
* Do not issue cipher findings for unverified STARTTLS sessions. No SMTP credentials are submitted.

## Evidence and limits
Starting HEAD: `17e147c76f6aa8c217ae8a1caeb89233c5e1ab28`.
Source commit: `2769b434631476843ae93b18e3d5f3480cd9f54e`.
Test commit: `821eee49041583b4f55874e2296f373fa08d05ed`.
Nine table-driven regression cases were added in `internal/smtpprobe/tls_integrity_test.go`.

GitHub connector confirms commits were published. Local repository checkout failed because `github.com` DNS could not resolve in the execution container. Full repository Go tests, final-HEAD CI, real Postfix/Dovecot host integration, and production TLS compatibility were **not** verified by this pass. This is not a beta-qualification record.

## Outstanding cumulative gates
Issues #1–#9 remain open. Real mail disposition/holds, durable delivery, protocol/authentication compliance, classifier accuracy and false-positive measurements, tenant policy enforcement, operational diagnostics, browser workflows, cold restore, and native update/rollback all require further implementation and independent acceptance evidence.
