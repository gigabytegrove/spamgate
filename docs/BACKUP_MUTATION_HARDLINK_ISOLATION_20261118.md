# Backup file mutation and hard-link isolation — 2026-11-18

Scope: issue #8, native Linux backup verification. These checks are read-only and do not alter Postfix, Dovecot, services, queues, or persistent SpamGate state.

- Inventory and verification now compare file identity, size and modification timestamp before and after streaming the checksum. A change detected during a scan fails the operation instead of issuing or accepting an apparently stable manifest.
- Linux descriptor-relative opening now rejects regular files with multiple hard links, including aliases outside the backup root. This avoids treating mutable external aliases as independent immutable backup content.
- Added Linux tests for within-tree and external hard links and a control for distinct ordinary files.

Limitations: timestamps can be restored, writes can occur between checks, and files can be changed after verification. These checks are not atomic snapshots, do not replace quiescence, and do not prove cold restore or production mail-host acceptance. The Linux hard-link restriction may reject backups created by tools that intentionally preserve hard links; such backups must be copied into independent regular files before signing. Do not relax the check without an explicit threat-model review.

Execution evidence: repository edits were committed through the GitHub connector. Local git checkout could not resolve github.com; local Go is 1.23.2 while go.mod requires 1.27.4. New tests, vet, CI and live-host acceptance must be treated as unverified until independent execution succeeds. Issues #1–#9 remain open.
