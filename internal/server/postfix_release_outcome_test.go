package server

import (
    "context"
    "errors"
    "fmt"
    "os"
    "os/exec"
    "strings"
    "testing"
)

func TestPostfixReleaseExecutionFailClosed(t *testing.T) {
    for _, tc := range []struct {
        name string
        err error
    }{
        {"exit70", &exec.ExitError{ProcessState: failedPostfixProcessState(t, 70)}},
        {"exit64", &exec.ExitError{ProcessState: failedPostfixProcessState(t, 64)}},
        {"wrapped", fmt.Errorf("private address recipient@example.test: %w", errors.New("failed"))},
        {"startup", &exec.Error{Name: "/private/mail/path", Err: os.ErrNotExist}},
    } {
        t.Run(tc.name, func(t *testing.T) {
            got := classifyPostfixReleaseExecution(tc.err)
            if !errors.Is(got, errPostfixReleaseOutcomeUnknown) {
                t.Fatalf("expected reconciliation sentinel, got %v", got)
            }
            for _, secret := range []string{"recipient@example.test", "/private/mail/path"} {
                if strings.Contains(got.Error(), secret) {
                    t.Fatalf("confidential error leaked %q", secret)
                }
            }
        })
    }
    if classifyPostfixReleaseExecution(nil) != nil {
        t.Fatal("nil execution error must remain nil")
    }
}

func failedPostfixProcessState(t *testing.T, code int) *os.ProcessState {
    t.Helper()
    // ExitError is deliberately constructed from a real child process so
    // ExitCode is portable across supported Linux Go toolchains.
    cmd := exec.Command("sh", "-c", fmt.Sprintf("exit %d", code))
    if err := cmd.Run(); err == nil {
        t.Fatal("expected subprocess failure")
    }
    return cmd.ProcessState
}

func TestPostfixReleaseCompletionCancellationRace(t *testing.T) {
    live, cancelLive := context.WithCancel(context.Background())
    defer cancelLive()
    if got := classifyPostfixReleaseCompletion(live, nil); got != nil {
        t.Fatalf("successful live command must remain successful: %v", got)
    }
    canceled, cancel := context.WithCancel(context.Background())
    cancel()
    if got := classifyPostfixReleaseCompletion(canceled, nil); !errors.Is(got, errPostfixReleaseOutcomeUnknown) {
        t.Fatalf("canceled successful child must require reconciliation: %v", got)
    }
    private := errors.New("recipient@example.test /private/mail/spool")
    for _, ctx := range []context.Context{live, canceled} {
        got := classifyPostfixReleaseCompletion(ctx, private)
        if !errors.Is(got, errPostfixReleaseOutcomeUnknown) {
            t.Fatalf("failed command must require reconciliation: %v", got)
        }
        if strings.Contains(got.Error(), "recipient@example.test") || strings.Contains(got.Error(), "/private/mail/spool") {
            t.Fatal("subprocess failure disclosed private metadata")
        }
    }
}
