# Classifier evaluation provenance — 2026-11-15

The offline `spamgate-eval` JSON result now includes `qualification` evidence. It records whether strict qualification, unique message digests and disjoint cohort checks were requested; whether a complete-file SHA-256 was verified; the verified corpus digest (when present); accepted record count; and input budgets. It never emits a corpus filesystem path or raw mail content.

A digest is marked verified only after the existing whole-file SHA-256 comparison and file/path stability checks succeed. A missing digest is explicitly unverified, not a zero hash. The qualification flag identifies the requested evaluation profile, **not** certification of a mail host. A passing offline corpus report does not demonstrate representativeness, operational false-positive rates, Postfix/Dovecot behavior, delivery, restore or rollback.

Regression coverage: `qualification_evidence_test.go` tests unpinned reporting, a pinned 4,000-record two-cohort strict evaluation and path confidentiality. Source publication is not test execution. Confirm exact-HEAD engineering CI and isolated mail lab separately; production qualification remains open.

Locked deployment: `/opt/spamgate/spamgate` foreground launcher, `spamgate-worker`, `/opt/spamgate/data` persistent storage, Milter ports 38470 and 38472. No running mail-server changes.
