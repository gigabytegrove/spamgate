# Reject-specific false-positive confidence gate — 2026-11-15

The evaluator now separately counts outright SMTP rejection of independently adjudicated legitimate messages. A tagged or quarantined legitimate message still contributes to the overall false-positive rate, but does **not** count as an outright reject.

Use `--max-reject-fpr-upper=0.001` to require the two-sided Wilson 95% upper confidence bound on rejected ham to be at most 0.1%. The default value 1 preserves previous CLI acceptance semantics until operators explicitly enable the stricter gate. The JSON report always includes the rejection counts, confidence bound, configured threshold, and pass/fail result. Reject counts also appear in each cohort's confusion matrix. The new gate is additional to overall false-positive, recall, precision and optional cohort gates.

This is a corpus-only offline safety gate. The corpus must be independently adjudicated and representative; a passing run is **not** proof of production Postfix/Dovecot delivery, Milter holds, SMTP authentication interoperability or live false-positive rates. No running mail server is changed.

Verification: new unit and CLI regression tests committed. Full Go tests and exact-HEAD CI must be inspected before acceptance.
