# Classifier corpus qualification (2026-11-20)

Native, read-only offline evaluator: `go run ./cmd/spamgate-corpus-eval -input corpus.jsonl -threshold 0.5 -min-precision 0.99 -min-recall 0.90 -max-fpr 0.001`.

Input is one JSON object per line: `{"id":"sample-1","truth":"spam","score":0.95}` or `{"id":"sample-2","truth":"clean","score":0.02}`. IDs must be unique; truth must be spam or clean; scores are normalized 0..1. Include both classes and independently labeled samples. Output is machine-readable confusion counts, precision, recall, false-positive rate and threshold. Exit 0 means all configured acceptance limits passed, 1 means an acceptance limit failed, 2 means invalid arguments/corpus or IO failure. This command never modifies mail, policy, or service state.

The evaluator is not a substitute for a real held-out labeled corpus, classifier integration, per-tenant stratification, confidence intervals, or an independently measured false-positive budget. The sample score is supplied by the caller; there is no claim that production classifier scores are currently exported in this format. Corpus size, sampling provenance, duplicates across training/evaluation sets and message privacy remain external qualification gates.

Local isolated Go 1.23 execution of `go test -v main.go main_test.go` passed 3 tests before GitHub publication. Full repository Go 1.27.4 compilation and final-commit GitHub Actions results remain unverified. All issues #1-#9 remain open. The October 31 beta deadline passed. No Postfix/Dovecot service or running mail host was touched.
