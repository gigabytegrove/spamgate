# Classifier duplicate-evidence hardening — 2026-11-18

## Change
The offline provenance qualification gate now rejects repeated message-family IDs and repeated content SHA-256 digests **within each dataset**, in addition to the preexisting cross-dataset isolation checks. This prevents repeated near-identical examples from being treated as independent evidence and artificially increasing the apparent confidence of threshold metrics.

The gate remains fail-closed and advisory. It does not change live classification or tenant policies. A corpus containing legitimate multiple samples from one message family must be deduplicated or grouped by the corpus owner before qualification; this is intentional, not a claim that such messages are invalid mail.

## Tests and evidence
Four table-driven regressions added: repeated tuning family, repeated tuning content, repeated holdout family, repeated holdout content. Existing isolation, chronology, tenant and sample-ID tests remain. GitHub writes verified; Go compilation and tests require CI confirmation. No production mail host was accessed.

## Remaining production gates
Issues #1–#9 remain open. Independent labeling, representative corpora, measured false-positive bounds, Postfix/Dovecot acceptance, durable delivery, SMTP authentication, tenant enforcement, browser tests, disaster recovery and native update/rollback remain mandatory. The native launcher /opt/spamgate/spamgate, worker spamgate-worker, persistent /opt/spamgate/data and Milter ports 38470/38472 are unchanged. No Docker substitution and no automatic mail-server changes.
