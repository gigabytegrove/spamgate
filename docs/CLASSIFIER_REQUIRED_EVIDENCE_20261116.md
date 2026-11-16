# Classifier qualification: required evidence (2026-11-16)

The offline `spamgate-classifier-eval` command rejects samples missing any of `id`, `tenant`, `spam`, or `score`, rejects explicit JSON `null` for those fields, rejects non-boolean labels and non-numeric scores, and rejects null or non-array corpora. Explicit `spam:false` and `score:0` remain valid. Validation runs after duplicate-key and nesting checks but before typed decoding, metrics, audits, and gate evaluation. On failure, the command emits no JSON report and exits nonzero.

**Why:** Go's ordinary struct JSON decoding defaults an absent boolean label to `false` and an absent numeric score to `0`. This could silently reclassify unlabeled examples as legitimate and distort tenant false-positive/recall evidence. The change is limited to offline qualification and does not alter live mail handling, Postfix, Dovecot, the worker, or the native Linux launcher.

**Verification required:** `go test ./cmd/spamgate-classifier-eval ./internal/qualification`, repository-wide Go race/vet and exact-commit CI; independently labeled representative production-scored corpora and real mail-host acceptance remain outstanding. This change alone does not qualify any of issues #1-#9 or the overdue beta.
