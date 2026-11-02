# SMTP relay authentication boundary — 2026-11-02

Production gates: [#3](https://github.com/gigabytegrove/spamgate/issues/3), [#6](https://github.com/gigabytegrove/spamgate/issues/6).

## Corrected failure mode

Environment loading rejected a username with plaintext SMTP, but `Relay.Send` could also be invoked with a directly constructed `Relay`. On a loopback SMTP endpoint, Go's `smtp.PlainAuth` can permit cleartext authentication; therefore relying on the environment loader alone was insufficient. A configured password without a username was also silently ignored, and a username without a password could attempt an empty-password login.

## Enforced contract

* Both environment construction and every `Relay.Send` call validate TLS mode, numeric port, host framing and authentication fields before opening a TCP connection.
* Authentication is never attempted in `none` mode, including to localhost. `none` remains supported for unauthenticated, explicitly configured relay hops.
* Username and password must both be present or both absent. Embedded NUL, CR and LF are forbidden in either credential field.
* `required` still demands STARTTLS, `implicit` still performs verified TLS before SMTP, and existing upstream SMTP capability checks remain mandatory.
* Validation errors contain no passwords. No automatic configuration changes, mail-server restarts or Docker substitutions.

## Regression scope

`go test ./internal/transport -run 'TestRelayConfigurationValidation|TestRelayFromEnvRejectsIncompleteAndPlaintextCredentials|TestRelaySendRejectsUnsafeAuthenticationBeforeDial' -count=1`

The TCP regression asserts that an invalid directly constructed relay is rejected **before any socket is accepted**. The normal engineering workflow runs the entire Go test and race suites, while the disposable Postfix/Dovecot workflow provides broader mail-path regression.

## Remaining qualification

This is a configuration and security regression gate, **not** independent interoperability certification against production SMTP AUTH implementations, ISPConfig or real production credentials. All nine cumulative production issues remain open pending their respective acceptance evidence. The October 31 beta deadline has passed; no beta readiness is claimed.
