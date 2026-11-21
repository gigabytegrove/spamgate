# Native spool audit: integrity gate reasons (2026-11-21)

## Scope

The read-only `spamgate-spool-audit -json` command now emits a nonempty `gate_failures` array whenever the completed audit reports integrity findings. Previously, `gate_passed=false` could accompany an empty `gate_failures` array when no queue-size threshold was configured.

The existing `-max-queued`, `-max-dead`, and `-max-pending` failures retain their order and wording. Integrity failures follow, sorted lexically by finding code, as `integrity:<code>=<count>`. They contain neither message contents nor queue identifiers. Truncated diagnostics also emit `integrity:findings_truncated`. Inconsistent in-memory reports fail closed with `integrity:unclassified_findings`.

Exit codes remain 0 for a complete clean audit, 1 for a completed audit with findings or threshold violations, and 2 for an incomplete audit or invocation/output error. Incomplete scans do not emit a success report. The command does not retry, delete, promote or otherwise alter queued messages.

## Qualification evidence

Source was inspected at starting HEAD `94e3aca32ea97debd707607e32a683a1ce9f28ef`. Added integration regression for JSON failure reasons and unit regressions for ordering, truncation and inconsistent reports. Commits were published through the GitHub contents API. Go tests and full Linux builds were **not executed** in this pass. The commit-status endpoint returned no statuses, and the connector's workflow-run lookup only covers pull-request-triggered runs, so push-triggered CI cannot be certified from that lookup.

This is a diagnostics improvement under issues #2 and #6, **not** proof of durable SMTP delivery, live Postfix/Dovecot integration, or production-host acceptance. All nine production gates remain open. Preserve the native launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, persistent `/opt/spamgate/data`, and Milter ports 38470/38472. No running mail-host configuration changes are authorized by this work.
