package server

import (
    "errors"
    "os/exec"
)

// errPostfixReleaseOutcomeUnknown is deliberately not exposed as a raw
// subprocess error: sudo and Postfix may include sensitive host information.
// Once a subprocess was launched, its failure does not prove that the queue
// mutation did not happen. The durable release_attempted state blocks retries.
var errPostfixReleaseOutcomeUnknown = errors.New("Postfix release outcome unknown; reconcile queue before retry")

// classifyPostfixReleaseExecution treats every failure after command launch as
// indeterminate. In particular, helper exit 70 explicitly signals uncertainty,
// while exit 64 may be a helper refusal or a sudo failure. A caller cannot
// safely prove the queue was untouched from a process exit status alone.
func classifyPostfixReleaseExecution(err error) error {
    if err == nil {
        return nil
    }
    var exitErr *exec.ExitError
    if errors.As(err, &exitErr) {
        // Keep exit codes out of public diagnostics; the caller needs only
        // the fail-closed classification, not subprocess stderr.
        return errPostfixReleaseOutcomeUnknown
    }
    // Context cancellation, pipe failure and failure to start the command
    // cannot be distinguished reliably at this boundary without a durable
    // child-start acknowledgement. Fail closed rather than risk a duplicate.
    return errPostfixReleaseOutcomeUnknown
}
