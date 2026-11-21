# Classifier evidence schema hardening — 2026-11-20

Issue #5: the JSONL evaluator previously decoded into a Go struct. That permitted omitted `score` to silently become zero and duplicate `score` or `truth` keys to silently override prior evidence. These conditions can bias the reported false-positive and recall gates.

The evaluator now requires `id`, `truth`, and `score` exactly once in each JSON object; rejects null, unknown keys, non-object records, malformed types and trailing JSON; and continues to reject duplicate sample IDs, out-of-range scores, and corpora without both labels. Field order and legitimate numeric zero remain valid.

Files: `cmd/spamgate-corpus-eval/sample_validation.go`, `sample_validation_test.go`, `main.go`. Regression coverage includes eleven malformed cases plus reordered fields and valid zero scores.

Evidence boundary: source commits are published on main. GitHub DNS resolution blocked a local checkout; final-HEAD tests and CI were not confirmed at authoring time. The corpus tool still consumes externally supplied labels and scores; it does not execute the production classifier or certify false-positive performance. Issues #1–#9 remain open. Native foreground launcher, worker, persistent data and Postfix Milter ports are unchanged; no running mail server was touched.
