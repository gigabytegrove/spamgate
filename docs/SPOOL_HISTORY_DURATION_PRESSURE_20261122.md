# Duration-based queue-pressure evidence — 2026-11-22

Scope: issues #2 and #6, diagnostic evidence only. Native `spamgate-spool-history` now accepts `-min-queued-pressure-duration`, `-min-delivering-pressure-duration`, and `-min-pending-pressure-duration` as Go duration values (for example `5m`). Each is disabled by default (zero). Negative values are invalid (exit 2). The existing `-max-queued-count`, `-max-delivering-count`, and `-max-pending-count` define the strict breach threshold; disabled count limits do not participate. The new checks retain prior failures and return exit 1 for an operational breach.

A duration failure requires at least two consecutive observations above the corresponding ceiling and elapsed capture time between the first and last observation greater than or equal to the requested duration. A single sample cannot establish elapsed time. The comparator rejects missing, equal, or unordered timestamps, negative counts, and incomplete evidence. This is sampled evidence, **not proof of uninterrupted queue pressure between observations**; configure `-max-snapshot-gap` to limit the largest unobserved interval. Since absolute ceiling gates already fail on any above-ceiling observation, duration failures are supplementary root-cause evidence rather than an alternative enforcement mode.

Architecture remains locked: permanent foreground launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, persistent `/opt/spamgate/data`, Milter ports 38470/38472. No Docker substitution or mail-host changes.

## Qualification evidence

GitHub source commits were published. Regression tests were committed but **not executed**: the available local Go toolchain is 1.23.2 versus the repository's newer requirement, and `git ls-remote` failed because github.com could not be resolved. Final-HEAD GitHub commit-status query returned no statuses, and the available workflow-run lookup only searches pull-request-triggered runs and returned none. These results do **not** prove CI success or failure. No production Postfix/Dovecot host was accessed.

## Outstanding gates

Issues #1–#9 remain open. This change does not establish Postfix/Dovecot final disposition, accepted-message durability, SMTP/authentication compliance, classifier false-positive rates, tenant policy enforcement, browser acceptance, backup/restore, or native update/rollback. The October 31 beta target has passed. Do not declare beta-qualified without independent end-to-end host and regression evidence.
