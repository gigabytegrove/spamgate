# SMTP enhanced-reply evidence boundary — 2026-11-20

Scope: GitHub issues #3 and #6. Native launcher, worker, persistent data path, and Milter ports are unchanged. No mail-host configuration is modified.

## Change

The enhanced reply parser now bounds line count to 100 and each reply text line to 512 bytes, rejects CR/LF/NUL, accepts only ASCII SP/HTAB token separators, requires canonical decimal enhanced status components without leading zeros, and refuses reply classes other than 2xx, 4xx, and 5xx. Contradictory multiline statuses remain untrusted. Manually supplied Result fields undergo the same validation before findings are emitted. No free-form reply text is retained.

## Evidence and limits

Starting main HEAD: aa9422c6aad96d3233c538a0e585c4f551defe58. Its engineering qualification run 44691691716 and isolated Postfix/Dovecot run 44691691672 both concluded success (checked 2026-11-20). The new parser and boundary tests were executed in an isolated Go 1.23.2 harness with local type stubs; all 16 test functions/subtests passed. This is not a full repository test and does not validate compatibility with the repository's Go 1.27.4 module. GitHub DNS was unavailable from the local container; GitHub connector writes were used. Final-HEAD Actions conclusions must be inspected separately.

## Outstanding acceptance

Issues #1–#9 remain production gates. This change does not demonstrate SMTP AUTH, durable mail delivery, classifier false-positive rates, tenant isolation, browser acceptance, disaster recovery, live Postfix/Dovecot holds or ISPConfig persistence. No real mail host was touched. October 31 beta deadline has passed; do not claim beta qualification without complete end-to-end and regression evidence.
