# SMTP stage-latency evidence — 2026-11-18

Scope: GitHub issue #6; observational SMTP probe only. The permanent native Linux launcher, worker, persistent data path and Milter ports are unchanged. No mail-host configuration was modified.

The probe now records four optional stage durations (milliseconds): greeting read, initial EHLO command/reply, STARTTLS command/reply, and post-TLS EHLO command/reply. Existing total probe and TLS handshake durations remain. Values are monotonic elapsed times rounded up to one millisecond. Zero/omitted values mean the stage was not completed or not attempted; a failed read after starting a stage retains elapsed evidence. These values are not SMTP delivery, credential-authentication or policy-compliance proof.

Regression coverage uses a real loopback SMTP peer with delayed greeting and EHLO, JSON field assertions, an interrupted greeting and zero durations for unattempted stages.

Commit-time evidence: source changes and tests pushed to main; the full Go test suite, race checks, browser acceptance and real production mail-host tests were not executed in this engineering environment. GitHub Actions must be inspected for the final commit and any failures corrected. The October 31 beta deadline has passed; issues #1-#9 remain open until independent acceptance evidence exists.

Outstanding: durable delivery and holds, ISPConfig-safe Dovecot/Postfix integration, classifier false-positive measurement, tenant enforcement, persistent diagnostic history, full browser tests, cold recovery and native update/rollback qualification.
