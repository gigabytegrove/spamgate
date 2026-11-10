# Native recovery manifest namespace validation — 2026-11-10

## Scope
The offline recovery verifier rejects manifest file paths that collide with declared directories, treat another declared file as a parent, or reference a parent omitted from the schema v2/v3 directory inventory. These checks occur during manifest parsing, before payload verification and before restore staging.

## Threat model
A malicious or malformed manifest can describe an impossible filesystem tree, such as a regular file named `messages` while `messages` is also a directory, or a file named `missing/child` without declaring `missing`. Rejecting contradictions early prevents filesystem-dependent errors from obscuring the cause of refusal. Legacy schema v1 does not require a directory inventory, but still rejects a file used as the parent of another file.

## Verification and limits
Three subprocess regression cases are committed in `scripts/test-spamgate-offline-data.py`. The engineering workflow already invokes that script. The commit does not establish passing CI, real-host recovery, database consistency, ACL/UID/GID preservation, or safe live snapshotting. Operators must stop SpamGate before snapshot and restore; the acknowledgement flag is not a service-state detector.

## Architecture
This is an offline tool only. The permanent foreground launcher remains `/opt/spamgate/spamgate`, the worker remains `spamgate-worker`, and persistent state remains `/opt/spamgate/data`. No Docker substitution, Postfix Milter port change, or automatic mail-server mutation is introduced.
