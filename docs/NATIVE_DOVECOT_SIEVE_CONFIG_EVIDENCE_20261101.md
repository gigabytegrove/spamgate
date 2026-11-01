# Native Dovecot LDA Sieve read-only evidence (2026-11-01)

The host probe now supports an **explicit opt-in** configuration and installed-file integrity check:

```bash
python3 scripts/spamgate-host-probe.py --check-dovecot-sieve
```

The default probe remains read-only and does not execute this additional check. The option invokes only `doveconf -n` with a five-second timeout. It requires an explicit `protocol lda` section with the `sieve` mail plugin and a global `plugin` section with `sieve_before = /etc/dovecot/sieve/spamgate-junk.sieve`. It checks the installed Sieve source, compiled `.svbin`, and Dovecot snippet against the exact three-entry SHA-256 manifest written by the opt-in native Sieve installer. Symlinks, missing/empty files, unsafe file modes, unexpected manifest entries, and checksum drift fail the diagnostic. Raw `doveconf` output, mailbox data and file contents are never included in the JSON report.

This is **not** proof of active Dovecot configuration, correct Sieve execution, mailbox placement or end-to-end Postfix delivery. LMTP is not certified, nor is ISPConfig-safe persistence. The script never restarts Dovecot, changes configuration, executes Sieve, or sends mail. If the option is combined with explicitly authorized `--send`, a failed check blocks submission.

The tests are hermetic: fake `doveconf`, nested LMTP vs LDA scope, malformed and duplicate sections, missing/changed compiled files, symlinks, manifest tampering, unsafe permissions, privacy of command failures, and SMTP suppression. Real production-host verification remains outstanding under issues #1, #6, #9.

The disposable Postfix/Dovecot CI lab also runs the read-only check against a real `doveconf -n` snapshot and root-owned installed Sieve files, and verifies it fails after the opt-in Sieve rollback. This remains isolated CI evidence, not a production-host qualification.

## Explicit LMTP configuration evidence (2026-11-01)

The same read-only verifier now supports a selected LMTP path:

```bash
python3 scripts/spamgate-host-probe.py --check-dovecot-sieve --dovecot-delivery-path lmtp
```

The original `--check-dovecot-sieve` default remains **LDA** for backward compatibility. The LMTP option checks the **top-level `protocol lmtp`** `mail_plugins` setting for an explicit `sieve` token, plus the same global `sieve_before` rule and manifest-verified files. It never infers LMTP enablement from an LDA stanza, or LDA enablement from LMTP. Duplicate LMTP sections/settings, malformed nested sections, and an absent plugin fail closed. The report records `delivery_path`, a path-specific scope and limitations; it never includes raw configuration. Specifying the path without `--check-dovecot-sieve` is an argument error.

**Important:** This does not verify that Postfix routes mail to LMTP, that Dovecot listens on a configured LMTP socket, that the selected Dovecot protocol is active, or that any Sieve rule executed. Neither a successful LDA nor a successful LMTP snapshot proves final mailbox placement or ISPConfig persistence. The operator must select the actual path based on independently verified Postfix transport configuration and test delivery in a disposable or authorized mail host. The probe remains opt-in, read-only and never changes running mail services.

New hermetic regressions exercise LDA/LMTP isolation, malformed/duplicate LMTP settings, missing Sieve rule, CLI gating, direct-library invalid modes, and privacy-safe output. The isolated lab additionally asserts that its explicit LDA configuration check is scoped to LDA; it does not claim LMTP delivery qualification.
