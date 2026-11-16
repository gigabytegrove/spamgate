# Offline classifier false-positive gates (2026-11-15)

The existing `spamgate-classifier-eval` reads labeled JSON samples from stdin and does not alter message routing, live policy, or the running mail server.

## Opt-in acceptance

```sh
go run ./cmd/spamgate-classifier-eval -threshold 5 -max-fp-upper 0.01 -min-clean 1000 -z-score 1.6448536269514722 < labeled-corpus.json
```

The process exits nonzero when any tenant or the aggregate fails. Output includes the evaluation and per-tenant gate reasons. Without `-max-fp-upper`, the previous evaluation-only output format is preserved.

The one-sided Wilson upper confidence bound is used rather than treating zero observed false positives as zero risk. Each tenant must independently meet the minimum clean sample count and bound; a large tenant cannot conceal a small tenant's failures. Sample IDs must be unique, labels independent, and the corpus representative. This tool evaluates supplied scores only; it does not produce classifier scores, measure drift, verify label provenance, or test MIME, malware, phishing, archive bombs, or SMTP delivery.

A 1% upper bound with zero false positives requires approximately 269 clean samples at z=1.645, but production acceptance must use a much larger, representative corpus and documented sampling protocol. No acceptance is claimed from synthetic tests.

## Evidence and boundaries

No production Postfix/Dovecot host was changed. Issues #1-#9 remain open. Required: independently labeled ham/spam across tenants, source attribution and holdout sets, repeated runs against the production classifier, false-negative and poisoning/drift limits, live delivery and hold evidence, browser acceptance, backup/restore, and native update/rollback. The October 31 beta target has passed; do not call this beta-qualified.
