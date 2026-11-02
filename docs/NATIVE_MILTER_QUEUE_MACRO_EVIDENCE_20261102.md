# Milter queue-ID macro evidence integrity — 2026-11-02

Production gates: #1 Postfix HOLD/disposition, #3 Milter protocol correctness, #6 diagnostics.

## Corrected failure mode

The Milter previously treated malformed `D` macro packets and invalid `i` values as if no queue-ID macro had arrived. If a valid queue ID had already been recorded in the same transaction, a subsequent malformed or duplicate queue-ID claim was silently ignored. The scan could then be saved with the earlier ID, creating ambiguous evidence for an administrator HOLD release.

Active transactions now distinguish an absent queue-ID macro from malformed queue-ID evidence. Unterminated packets, odd name/value pairs, duplicate `i`/`{i}` aliases, invalid or oversized nonempty IDs, and malformed brace aliases poison the current transaction. EOM requests SMTP temporary failure without recording a misleading scan. A subsequent transaction on the same connection can recover. Empty `i` values are accepted as unassigned (they never erase a previously observed nonempty ID), and unrelated well-formed macros remain allowed.

This change does not infer that a Postfix queue ID exists before Postfix actually supplies it. A transaction with no ID can still be scanned and its MTA disposition marked as requested, not confirmed. No queue manipulation is performed by this code.

## Verification and limitations

The new Go regressions cover parsing and in-process Milter wire responses, including an earlier valid ID followed by invalid evidence, duplicate aliases, recovery, empty IDs, and unrelated macros. The existing disposable Postfix/Dovecot CI integration must still pass on the exact commit.

This is not independent production Postfix conformance or a live ISPConfig mail-host qualification. The October 31 beta target has passed; all nine production gates remain open. The native launcher, worker, data root and Milter ports 38470/38472 are unchanged. No running MTA is modified.
