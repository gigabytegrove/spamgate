# Native backup verification cancellation — 2026-11-19

Starting main: c8909ea5f89781675b2f88e2c7f1ac2ac0b2ff42.

## Implementation
- Propagate the operator SIGINT/SIGTERM context through the native verify CLI into authenticated complete verification, inventory traversal, file hashing, and final descriptor-relative verification.
- Preserve the existing non-context API entry points for existing callers; add VerifyCompleteContext, BuildInventoryContext, and VerifyContext.
- Stop traversing or initiating additional reads after cancellation. Reject nil contexts and do not print success on cancellation.
- Add regression coverage for cancellation during a read, cancellation before verification, nil context, and successful complete verification.

## Verification boundary
This is an operator cancellation improvement, not an atomic snapshot. A read blocked in the kernel cannot be forcibly interrupted by a context check. Concurrent filesystem modification and privileged path replacement remain risks. Production mail-host tests have not been run. Go test execution and final-HEAD CI must be checked before qualification claims.

## Outstanding acceptance
GitHub issues #1–#9 remain open: real Postfix/Dovecot disposition, durable delivery, SMTP authentication, classifier accuracy and false-positive evidence, tenant policy enforcement, diagnostics, browser workflows, full disaster recovery, and native update/rollback. No running mail host was modified. Native architecture remains /opt/spamgate/spamgate, spamgate-worker, /opt/spamgate/data, and Milter ports 38470/38472.
