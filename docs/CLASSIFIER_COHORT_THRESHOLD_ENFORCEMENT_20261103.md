# Classifier cohort threshold enforcement — 2026-11-03

## Root cause
The evaluator computed cohort statistics but only applied them to the final exit status when `--require-cohorts` was enabled. Previously, users could explicitly configure cohort sample-size, false-positive and recall thresholds without that flag, receive exit 0, and mistake an unenforced cohort policy for a successful qualification. Positive cohort precision thresholds were guarded separately; this change closes the same bypass for the remaining four cohort thresholds.

## Behavior
Explicitly supplying `--min-cohort-ham`, `--min-cohort-spam`, `--max-cohort-fpr-upper`, or `--min-cohort-recall-lower` requires `--require-cohorts`, even when the supplied value equals the default. A positive `--min-cohort-precision-lower` also requires the cohort gate. Its documented zero value remains a disabled gate for backward compatibility. Invalid configuration exits 2 before opening the corpus or emitting a JSON report. With `--require-cohorts`, insufficient samples or bad measured confidence exits 3 with a full evaluation report. Default global-only evaluations continue to work.

## Verification boundary
The regression suite covers all explicit cohort thresholds, an explicitly disabled precision gate, global-only backward compatibility, and a measured cohort failure. Source changes were committed through the GitHub API. Local Git clone and full Go test execution were blocked by github.com DNS resolution in the execution container. Do not infer successful tests or CI from commits. Run `go test ./cmd/spamgate-eval` and `go test ./...` in a complete checkout and inspect exact-HEAD CI.

This change is evaluator configuration safety, not detection accuracy. All issues #1–#9 remain open until their respective end-to-end gates pass. Preserve native `/opt/spamgate/spamgate`, `spamgate-worker`, persistent `/opt/spamgate/data`, Milter ports 38470/38472. No mail-host changes.
