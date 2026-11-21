# Native spool-trend evidence opening — 2026-11-21

## Change
The Linux report reader now opens with O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK and verifies the opened descriptor against the initial lstat. This prevents final-component symlink substitution from redirecting reads and avoids blocking indefinitely on a substituted FIFO. Regular-file, size, identity and post-read metadata checks remain in Load. No SMTP messages or server configuration are changed.

## Scope and limitations
This does not secure untrusted parent-directory path traversal, bind mounts, hardlinks, or concurrent in-place mutation with restored metadata. Non-Linux builds retain the existing os.Open plus identity checks and do not claim O_NOFOLLOW. An attacker with write access to the evidence directory remains outside the proven trust boundary. Audit snapshots are not signed and their ordering, host provenance, and final mailbox placement remain unverified.

## Qualification
New Linux tests cover final symlink rejection, FIFO nonblocking behavior, and regular file opening. Run `go test ./internal/spooltrend ./cmd/spamgate-spool-trend` on Linux with the repository toolchain and inspect exact-HEAD CI. Production-host acceptance is still required. Issues #1–#9 remain open.
