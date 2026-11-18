# SMTP socket/context deadline race — 2026-11-18

## Verified starting evidence
- Starting main: `24b0902de454d5bb07449842cf3daba4bf69b77c`.
- Engineering workflow run 44290299676 failed in `TestProbeStalledGreetingDeadlineIsTimeout`: the TCP socket returned `i/o timeout` before `probeCtx.Err()` became observable. All other Go package tests in the non-race stage passed.
- Isolated Postfix/Dovecot workflow run 44290299610 succeeded at that earlier HEAD. This is **not** production mail-host qualification.

## Correction
- `internal/smtpprobe/probe.go` maps a socket timeout to `context.DeadlineExceeded` when the socket's exclusively context-derived deadline has elapsed. Explicit caller cancellation remains preserved. Successful protocol results and SMTP numeric rejections remain unchanged.
- `internal/smtpprobe/socket_deadline_race_test.go` repeats a stalled greeting with a short deadline and checks error identity, stage, and machine-readable failure kind.

## Limits
- The new test and final-HEAD workflow must complete before this correction can be called regression-qualified.
- All production issues #1–#9 remain open; no production Postfix, Dovecot, running mail service, or persistent data was changed.
- Native launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, data `/opt/spamgate/data`, and Milter ports 38470/38472 remain locked.
- October 31, 2026 target has passed. Do not label the build long-term beta-ready until end-to-end and real-host gates pass.
