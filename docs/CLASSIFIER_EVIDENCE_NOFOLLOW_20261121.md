# Native classifier evidence open hardening — 2026-11-21

Scope: issue #5, paired classifier evidence ingestion on native Linux. This does not qualify the production classifier or the mail host.

## Change
The evidence reader now opens input paths using Linux O_NOFOLLOW, O_CLOEXEC and O_NONBLOCK before converting the file descriptor to an os.File. It compares the opened regular-file inode with the inode observed by Lstat. This closes the final-component symlink substitution gap between Lstat and open. O_NONBLOCK prevents accidental blocking on a substituted FIFO; opened descriptors are rejected unless they reference regular files. Both baseline and candidate must reference distinct inodes.

## Tests
input_preflight_linux_test.go covers kernel nofollow enforcement, FIFO rejection, and inode preservation. Existing input_preflight_test.go covers identical paths, hardlinks, symlinks, directories, missing files and valid distinct corpora. Execution and CI must be verified on the final commit; committing tests is not a passing test result.

## Remaining limitations
This protects the final pathname component, not malicious replacement of parent directories. Concurrent in-place modification of an opened regular file remains possible; evidence must be generated into immutable, controlled files before qualification. Corpus size and memory use remain bounded only by available resources and the JSONL scanner's per-line limit. Scores are externally supplied rather than produced by the actual SpamGate classifier. No representative independently labeled corpus was evaluated.

## Production gates
GitHub issues #1-#9 remain cumulative acceptance gates: real Postfix/Dovecot disposition and HOLD, durable delivery, SMTP/authentication, production classifier accuracy and false positives, tenant runtime enforcement, diagnostics, complete browser UI, backup/restore, and native update/rollback. A passing isolated lab cannot substitute for real mail-host acceptance. Preserve /opt/spamgate/spamgate foreground launcher, spamgate-worker, persistent /opt/spamgate/data, and Postfix Milter ports 38470/38472. Do not replace native services with Docker or alter the live mail host automatically.
