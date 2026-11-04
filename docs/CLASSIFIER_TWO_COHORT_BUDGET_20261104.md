# Two-cohort corpus record-budget feasibility — 2026-11-04

Production gate: #5 (classifier evaluation). This change is not classifier detection improvement or mail-host qualification.

When `--require-cohorts` is set, the evaluator requires at least two disjoint cohorts, each containing `--min-cohort-ham` legitimate and `--min-cohort-spam` spam examples. Previously `--max-records` could be smaller than the minimum required across those two cohorts. The evaluator would read a corpus that could never satisfy the requested gate.

Before opening the corpus, the CLI now rejects configurations where `2 * (min-cohort-ham + min-cohort-spam) > max-records`. Division and subtraction avoid overflow at maximal signed integer inputs. The check applies only with `--require-cohorts`; report-only cohort defaults do not impose extra corpus requirements.

Tests: `go test ./cmd/spamgate-eval -count=1` and `go test ./... -count=1`. Added cases cover impossible ham/spam/combined budgets, huge integers, exact-fit successful cohorts, early rejection and report-only compatibility.

Verification limitation: the GitHub connector wrote source and tests, but the execution environment could not resolve github.com for a local checkout. Test execution and exact-HEAD CI must be independently verified. No Postfix, Dovecot, systemd, native deployment, or production host was modified. All issues #1–#9 remain open pending their independent acceptance evidence.
