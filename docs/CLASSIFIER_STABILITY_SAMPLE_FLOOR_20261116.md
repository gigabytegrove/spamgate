# Per-tenant threshold-stability evidence floor (2026-11-16)

The offline `spamgate-classifier-eval` command now supports `-min-stability-samples=N` alongside `-stability-margin=M -max-stability-flips=F`. A configured floor is applied independently to every tenant in the stability audit, including tenants whose observed flip fraction is zero. This prevents a tenant represented by only one or two examples from appearing qualified merely because its sensitivity fraction is below the configured limit.

Example (offline only, no mail-server changes):

```sh
spamgate-classifier-eval -expected-tenants=alpha,beta -stability-margin=0.5 -max-stability-flips=0.05 -min-stability-samples=1000 < labeled-corpus.json
```

The new option is opt-in for backward compatibility. Explicit zero/negative floors and floors without an enabled stability flip gate fail before reading corpus data or emitting a report. If the floor fails, the per-tenant `passed` and overall `passed` flags are false and the command returns a nonzero exit status after emitting the audit report. The floor counts all labeled examples, not separate clean/spam examples; use existing false-positive/recall gates and tenant inventory requirements for those independent checks.

## Qualification boundaries

This does **not** demonstrate accuracy on representative live mail, confidence intervals for threshold stability, or resistance to poisoned corpora. It does not modify Milter dispositions, Postfix/Dovecot, the native launcher, persistent state, or the update path. Real mail-host evidence and independent corpus acceptance remain required before closing issue #5 or declaring beta readiness.

## Verification status

Source and regression test committed. Local Git checkout cannot resolve github.com; local Go execution and exact-final-HEAD CI are not established by this document. Do not interpret this document as a passing test result.
