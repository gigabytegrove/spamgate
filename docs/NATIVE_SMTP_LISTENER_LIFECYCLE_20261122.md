# Native SMTP listener lifecycle and error logging — 2026-11-22

Scope: native SMTP ingress only. No changes to Postfix, Dovecot, systemd, the permanent /opt/spamgate/spamgate foreground launcher, spamgate-worker, /opt/spamgate/data or Milter ports 38470/38472.

The listener now registers its context-triggered socket close with context.AfterFunc and unregisters that callback when Listen exits. A listener that fails for reasons other than cancellation no longer retains a goroutine indefinitely waiting for a context that may never be cancelled.

All SMTP handler error paths use one nil-safe logger, including durable queue errors, relay preflight rejection, history write failure and downstream relay failure. Directly constructed SMTP instances without a logger no longer panic on those paths. Configured loggers remain authoritative.

Added regression tests for default/explicit logger selection, direct handler untrusted-peer refusal without logger injection, and preflight enforcement even when the caller context is cancelled.

Qualification: source committed. Complete Go tests, race tests, owner-controlled native Linux build, real Postfix/Dovecot integration and failure injection NOT EXECUTED. No GitHub Actions were used. The local checkout cannot resolve github.com and local Go is 1.23.2, below the repository's declared toolchain. No mail host or production service was modified.

This addresses one lifecycle resource leak and one nil-logger failure class; it does not complete durable delivery, actual Postfix holds, classifier accuracy, browser acceptance, backup/restore or native rollback. All production issues #1–#9 remain open. The October 31, 2026 beta target has passed.
