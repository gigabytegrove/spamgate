# Quarantine persistence safety — October 30, 2026

The quarantine original is now validated against the internal 32-character
scan ID, and symlinked quarantine directories are rejected. On Unix, the
quarantine directory's parent and each newly renamed original's directory
entry are fsynced before returning success to the SMTP ingress. Header
snapshot publication also gains parent-directory fsync via the shared
atomicBytes helper.

This improves crash durability and path integrity but does not prove
power-loss behavior on a particular filesystem or eliminate all possible
directory-replacement races by a privileged hostile local process. Full
cold-restore, fault-injection, and live mail-host qualification remain open.
