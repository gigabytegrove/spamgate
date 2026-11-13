# SMTP capability transition diagnostics — 2026-11-13

## Implemented
The read-only SMTP assessment now reports SIZE capability disappearance (`SIZE_NOT_ADVERTISED_AFTER_TLS`) and appearance (`SIZE_ADVERTISED_ONLY_AFTER_TLS`), independently of numeric SIZE limit changes. It also reports AUTH appearing only after STARTTLS (`AUTH_ADVERTISED_ONLY_AFTER_TLS`). These findings require verified STARTTLS and a successful post-TLS EHLO (250). A failed, absent, or unverified response is not interpreted as capability drift.

The findings do not submit SMTP AUTH credentials, accept mail, modify Postfix or Dovecot, or establish production compliance. Tests exercise nine transition and negative-evidence cases in `internal/smtpprobe/assessment_tls_capability_transition_test.go`.

## Verification and gates
GitHub source and prior assessment tests were inspected. Source and tests were committed to `main`. Local checkout and Go test execution were blocked because this execution environment could not resolve github.com. Exact-HEAD CI and real mail-host interoperability remain unverified. Do not claim beta qualification from these diagnostic tests.

## Locked deployment
Keep `/opt/spamgate/spamgate` as the foreground launcher, `spamgate-worker` as the worker, `/opt/spamgate/data` persistent, and Milter ports 38470/38472. No Docker substitution and no automatic running-mail-server changes.
