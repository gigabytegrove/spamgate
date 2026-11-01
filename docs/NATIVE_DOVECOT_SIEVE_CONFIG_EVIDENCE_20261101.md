# Native Dovecot LDA Sieve read-only evidence (2026-11-01)

The host probe now supports an **explicit opt-in** configuration and installed-file integrity check:

\`\`\`bash
python3 scripts/spamgate-host-probe.py --check-dovecot-sieve
\`\`\`

The default probe remains read-only and does not execute this additional check. The option invokes only \`doveconf -n\` with a five-second timeout. It requires an explicit \`protocol lda\` section with the \`sieve\` mail plugin and a global \`plugin\` section with \`sieve_before = /etc/dovecot/sieve/spamgate-junk.sieve\`. It checks the installed Sieve source, compiled \`.svbin\`, and Dovecot snippet against the exact three-entry SHA-256 manifest written by the opt-in native Sieve installer. Symlinks, missing/empty files, unsafe file modes, unexpected manifest entries, and checksum drift fail the diagnostic. Raw \`doveconf\` output, mailbox data and file contents are never included in the JSON report.

This is **not** proof of active Dovecot configuration, correct Sieve execution, mailbox placement or end-to-end Postfix delivery. LMTP is not certified, nor is ISPConfig-safe persistence. The script never restarts Dovecot, changes configuration, executes Sieve, or sends mail. If the option is combined with explicitly authorized \`--send\`, a failed check blocks submission.

The tests are hermetic: fake \`doveconf\`, nested LMTP vs LDA scope, malformed and duplicate sections, missing/changed compiled files, symlinks, manifest tampering, unsafe permissions, privacy of command failures, and SMTP suppression. Real production-host verification remains outstanding under issues #1, #6, #9.
