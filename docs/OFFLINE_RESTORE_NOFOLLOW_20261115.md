# Native Linux offline restore: no-follow file opens

The restored-tree verifier now opens persistent manifest files and ephemeral runtime locks with Linux O_NOFOLLOW and O_CLOEXEC. O_NONBLOCK prevents an unexpected FIFO replacement from hanging the verifier. Lstat, descriptor identity and hard-link checks remain in place. A symlink introduced between Lstat and open is rejected by the kernel rather than followed.

Linux regression coverage includes direct symlink refusal, symlinked manifest data and symlinked runtime locks. These tests are not production-host acceptance evidence.

Limitations: O_NOFOLLOW protects the final pathname component only. A privileged adversary able to rename ancestor directories during verification remains outside this offline, quiescent-tree threat model. The non-Linux implementation retains existing path-based behavior; the production target is native Linux. Do not run verification while SpamGate writers are active. No Postfix or Dovecot configuration is changed.
