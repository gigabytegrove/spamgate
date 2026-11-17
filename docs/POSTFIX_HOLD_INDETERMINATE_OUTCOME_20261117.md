# Postfix HOLD release: indeterminate outcome contract (2026-11-17)

Starting commit: 2599d73ce4a4599cc75d9e3be7d8ee9f46a0987d.

## Problem

A successful privileged `postsuper -H` invocation can be followed by failure to report the result to the worker. Retrying a queue mutation based solely on the reporting error risks acting on an already released queue ID or a reused ID. Likewise, cancellation after the child has run cannot prove that the queue remains held.

## Implementation

`cmd/spamgate-postfix-release/main.go` defines `errReleaseOutcomeUnknown`. Reporting errors, short writes, and cancellation observed after the child completes now wrap this sentinel; caller-visible messages remain fixed and confidential. The original context cancellation remains detectable with `errors.Is`. New tests cover both reporting-failure paths, secret redaction, and separation from pre-execution cancellation and validation.

This is a *helper-local* contract. The external process interface still emits a nonzero exit status; the worker does not yet consume a structured indeterminate result. **Do not automatically retry a failed HOLD release** without checking Postfix's current queue state and queue-ID identity. A nonzero subprocess exit or output overflow may also represent a partially applied action; this change does not prove otherwise.

## Acceptance limits

No real Postfix queue was modified. No Dovecot delivery, reused queue-ID reconciliation, persistence, or production-host acceptance was demonstrated. All issues #1–#9 remain open. Locked native Linux paths and Milter ports remain unchanged. The October 31 beta target has passed. This is not beta qualification.
