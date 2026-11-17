//go:build linux

package main

import (
 "bytes"
 "context"
 "errors"
 "os/exec"
 "strings"
 "testing"
)

func TestPostsuperExitStatusRetainedWithoutSensitiveOutput(t *testing.T) {
 private := "recipient=private@example.invalid queue=A1B2C3 path=/var/spool/postfix/private"
 path := helperScript(t, "printf '%s\\n' '"+private+"' >&2; exit 19")
 var sink bytes.Buffer
 err := runPostsuperCommand(context.Background(), path, []string{"-H", "A1B2C3"}, &sink)
 if err == nil { t.Fatal("nonzero subprocess exit accepted") }
 var exit *exec.ExitError
 if !errors.As(err, &exit) || exit.ExitCode() != 19 {
  t.Fatalf("expected typed exit status 19, got %v", err)
 }
 if strings.Contains(err.Error(), private) || strings.Contains(err.Error(), "private@example.invalid") || strings.Contains(err.Error(), "/var/spool/") {
  t.Fatalf("privileged subprocess data leaked in error: %q", err)
 }
 if sink.Len() != 0 { t.Fatalf("failed release wrote confirmation: %q", sink.String()) }
}

func TestPostsuperSuccessfulOutputCannotEscape(t *testing.T) {
 private := "recipient=private@example.invalid queue=A1B2C3 path=/var/spool/postfix/private"
 path := helperScript(t, "printf '%s\\n' '"+private+"'; printf '%s\\n' '"+private+"' >&2")
 var sink bytes.Buffer
 if err := runPostsuperCommand(context.Background(), path, []string{"-H", "A1B2C3"}, &sink); err != nil { t.Fatal(err) }
 if sink.String() != "Postfix HOLD release command completed\n" {
  t.Fatalf("unexpected release confirmation: %q", sink.String())
 }
 if strings.Contains(sink.String(), private) { t.Fatal("privileged output leaked") }
}

type sensitiveFailureSink struct{}
func (sensitiveFailureSink) Write([]byte) (int, error) {
 return 0, errors.New("recipient=private@example.invalid path=/var/spool/postfix/private")
}

func TestPostsuperSinkErrorCannotEscape(t *testing.T) {
 path := helperScript(t, "exit 0")
 err := runPostsuperCommand(context.Background(), path, nil, sensitiveFailureSink{})
 if err == nil || !strings.Contains(err.Error(), "reporting failed") { t.Fatalf("missing reporting failure: %v", err) }
 if strings.Contains(err.Error(), "private@example.invalid") || strings.Contains(err.Error(), "/var/spool/") {
  t.Fatalf("sink error leaked: %v", err)
 }
}

func TestPostsuperFailedCommandDoesNotUseSink(t *testing.T) {
 path := helperScript(t, "exit 7")
 marker := &countingSink{}
 err := runPostsuperCommand(context.Background(), path, nil, marker)
 if err == nil { t.Fatal("failed command accepted") }
 if marker.writes != 0 { t.Fatalf("failure wrote to result sink %d times", marker.writes) }
}

type countingSink struct { writes int }
func (s *countingSink) Write(p []byte) (int, error) { s.writes++; return len(p), nil }
