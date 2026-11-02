# Native delivery-policy witness and backup integrity — 2026-11-02

Production gates #4, #6 and #8. Implementation and automated regression evidence only; **not** production mail-host qualification.

## Failure mode

A permanent `.delivery-policy.initialized` file alone did not prove that a marker had ever existed: deleting only the marker while leaving valid counters let an already-running worker recreate it. After restart the same state was indistinguishable from a legacy pre-marker installation. That could conceal deletion of enforcement evidence.

## Contract

Newly persisted `delivery-policy.json` records include `"initialized": true`. A worker that reads a witnessed state without its permanent marker refuses startup and live policy evaluation; it does not recreate the marker, reset rate allowances or rewrite forensic evidence. A worker opened before another process's first publication also checks the freshly loaded witness under the Linux policy lock.

Legacy state without the witness is still readable. The first successful policy evaluation writes the marker, then a witnessed state. This migration window cannot distinguish malicious removal of both a legacy marker and its evidence from a genuinely old installation. The marker is not cryptographically authenticated and a privileged attacker who can rewrite both files can still forge state.

Cold backup creation and archive verification/restore reject a witnessed policy state missing its marker, even when ZIP hashes are internally consistent. Archive witness JSON is bounded and checked for ambiguous keys. Legacy unwitnessed backups remain supported. Offline backups still require stopped services and an actual real-host disaster-recovery drill.

No Docker substitution, Postfix configuration changes, service restarts or port changes are performed.
