# Paired classifier false-negative qualification — 2026-11-20

Production issue #5 remains open. This change extends the paired, independently labeled JSONL comparator with baseline/candidate false-negative rates and Wilson 95% upper confidence bounds for spam misses. Existing false-positive gates and sample-size gates remain in force.

New flags: `-max-candidate-fnr` and `-max-candidate-fnr-upper-95`, both inclusive values in [0,1], default 1 (nonrestrictive for compatibility). Invalid values, including NaN, fail with exit code 2. Threshold breaches return 1 after emitting JSON. New JSON fields: `baseline_false_negative_rate`, `candidate_false_negative_rate`, `baseline_false_negative_upper_95`, `candidate_false_negative_upper_95`.

The confidence bound is not a guarantee of operational recall. Both classes must be represented; a production acceptance threshold and representative, independently labeled corpus are still required. The comparator does not execute the production classifier, so classifier runtime integration and real false-positive/false-negative qualification remain unverified.

Also corrected a stale cold-restore regression expectation: the current preflight correctly rejects an already existing destination before parsing credentials or manifests. This is not a successful live restore qualification.

No production mail server was modified. The permanent foreground launcher, worker, persistent data path, and both Milter ports are unchanged. Real Postfix/Dovecot, durable delivery, SMTP compliance, tenant policy, browser workflows, backup/restore and native update/rollback remain independent open production gates. No beta-readiness claim is made.
