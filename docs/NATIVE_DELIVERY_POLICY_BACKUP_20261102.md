# Cold backup of native delivery-policy evidence — 2026-11-02

**Scope:** production gates #4 and #8. Implementation and regression evidence only; not real-host disaster-recovery qualification.

The persistent `.delivery-policy.initialized` marker and `delivery-policy.json` counters are both included in a cold native backup and restored together. The separate `.delivery-policy.lock` is an ephemeral Linux flock inode and must **never** be restored: stale root-owned lock files can prevent an unprivileged native worker from evaluating mail policy. The runtime-lock exclusion list now includes this file for new archives and legacy archives, while retaining the marker.

The regression creates a real core Store, writes rate-limit state, creates/verifies/restores a ZIP, reopens the restored Store and proves the pre-backup counter still enforces the hourly ceiling. It also proves the marker and counters are present and the lock is absent. Existing archive verification still hashes legacy excluded lock entries before skipping extraction.

Cold backups require SpamGate stopped; this is not a substitute for real power-loss, disk-full, ISPConfig integration or a production restore drill. No running Postfix or Dovecot configuration is changed.

Backup creation now refuses an initialized marker without `delivery-policy.json`; archive verification and restoration independently reject the same inconsistent pair even when a forged archive has self-consistent hashes. A new negative regression verifies that an incomplete backup is never published and an incomplete archive never publishes a restored directory. Legacy archives containing policy state but no marker remain accepted for upgrade compatibility.
