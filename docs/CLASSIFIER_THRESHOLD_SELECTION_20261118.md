# Offline classifier threshold selection and holdout boundary — 2026-11-18

Issue area: classifier accuracy, false positives and tenant-specific qualification.

The new `SelectQualifiedThreshold` function evaluates a supplied threshold grid against the existing Wilson upper false-positive bound, Wilson lower precision bound, and Wilson lower recall bound. Each gate must pass overall and for every tenant. The selection is advisory and does not change a running policy, Postfix, Dovecot, or mail disposition.

Candidate ranking: maximize observed recall, then minimize false-positive count, then choose the higher threshold. If no candidate qualifies, `selected` is absent. All failed candidates retain gate reasons for inspection.

`ValidateIndependentHoldout` rejects sample-ID reuse across tuning and holdout datasets, including cross-tenant reuse. This is only a minimal leakage check. It cannot prove message-family independence, corpus representativeness, label quality, or production performance.

**Production acceptance remains blocked** until a separately collected, independently labeled holdout corpus is evaluated, with tenant-by-tenant confidence bounds and live mail-host evidence. Threshold optimization on its own tuning corpus is not proof of classifier quality. No production policy mutation is performed.

Locked architecture remains `/opt/spamgate/spamgate`, `spamgate-worker`, `/opt/spamgate/data`, Milter ports 38470/38472; no Docker substitution or live mail-server changes.
