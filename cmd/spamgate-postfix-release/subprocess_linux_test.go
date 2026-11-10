//go:build linux

package main

import (
 "bytes"
 "context"
 "errors"
 "io"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func helperScript(t *testing.T, body string) string {
 t.Helper()
 dir := t.TempDir()
 path := filepath.Join(dir, "postsuper-fixture")
 if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil { t.Fatal(err) }
 return path
}

func TestPostsuperSubprocessCombinedOutputLimit(t *testing.T) {
 // 5 KiB on each stream individually fits; combined output must fail.
 path := helperScript(t, "head -c 5120 /dev/zero | tr '\\000' x; head -c 5120 /dev/zero | tr '\\000' y >&2")
 var out bytes.Buffer
 err := runPostsuperCommand(context.Background(), path, []string{"-H", "A123"}, &out)
 if err == nil || !strings.Contains(err.Error(), errOutputLimit.Error()) { t.Fatalf("combined budget not enforced: %v", err) }
 if out.Len() != 0 { t.Fatalf("failure reported success output: %q", out.String()) }
}

func TestPostsuperSubprocessExitFailure(t *testing.T) {
 path := helperScript(t, "echo 'queue ID not found' >&2; exit 7")
 var out bytes.Buffer
 err := runPostsuperCommand(context.Background(), path, nil, &out)
 if err == nil || !strings.Contains(err.Error(), "queue ID not found") { t.Fatalf("missing diagnostic: %v", err) }
 if out.Len() != 0 { t.Fatal("failed command produced success output") }
}

func TestPostsuperSubprocessSuccess(t *testing.T) {
 path := helperScript(t, "echo 'postsuper: Released: 1 message' >&2")
 var out bytes.Buffer
 if err := runPostsuperCommand(context.Background(), path, nil, &out); err != nil { t.Fatal(err) }
 if !strings.Contains(out.String(), "Released: 1 message") { t.Fatalf("missing successful output: %q", out.String()) }
}

func TestPostsuperSubprocessCancellation(t *testing.T) {
 path := helperScript(t, "exec sleep 10")
 ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
 defer cancel()
 var out bytes.Buffer
 started := time.Now()
 err := runPostsuperCommand(ctx, path, nil, &out)
 if !errors.Is(err, context.DeadlineExceeded) { t.Fatalf("timeout not propagated: %v", err) }
 if time.Since(started) > 3*time.Second { t.Fatal("subprocess was not terminated promptly") }
 if out.Len() != 0 { t.Fatal("timed-out command produced success output") }
}

func TestPostsuperDiagnosticSanitization(t *testing.T) {
 cases := []struct{ name, raw, want string }{
  {"newline injection", "missing queue\nSpamGate: released", "missing queue SpamGate: released"},
  {"terminal escape", "\x1b[31merror\x1b[0m", "error"},
  {"invalid utf8", "bad\xffinput", "bad input"},
  {"tabs and carriage returns", "a\tb\rc", "a b c"},
  {"OSC title injection", "\x1b]0;FAKE SUCCESS\x07error", "error"},
  {"bidi spoofing", "safe\u202eevil\u202c text", "safe evil text"},
  {"unicode line separator", "first\u2028second", "first second"},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   if got := safePostfixDiagnostic([]byte(tc.raw)); got != tc.want {
    t.Fatalf("sanitized diagnostic = %q, want %q", got, tc.want)
   }
  })
 }
}

func TestPostsuperSubprocessFailureCannotInjectLogLines(t *testing.T) {
 path := helperScript(t, "printf 'queue missing\\nFAKE SUCCESS\\033[31m\\n' >&2; exit 7")
 var out bytes.Buffer
 err := runPostsuperCommand(context.Background(), path, nil, &out)
 if err == nil { t.Fatal("nonzero postsuper exit accepted") }
 if strings.Contains(err.Error(), "\n") || strings.Contains(err.Error(), "\x1b") {
  t.Fatalf("unsafe subprocess diagnostic: %q", err.Error())
 }
 if out.Len() != 0 { t.Fatal("failed subprocess produced success output") }
}


func TestPostsuperOutputLimitTakesPrecedenceOverExitStatus(t *testing.T) {
 // A child can emit too much output and also exit unsuccessfully.
 // The resource-limit violation must not be hidden behind its exit code.
 path := helperScript(t, "head -c 16384 /dev/zero | tr '\\000' x >&2; exit 17")
 var out bytes.Buffer
 err := runPostsuperCommand(context.Background(), path, nil, &out)
 if !errors.Is(err, errOutputLimit) {
  t.Fatalf("want output-limit sentinel, got %v", err)
 }
 if out.Len() != 0 { t.Fatalf("failed command produced success output: %q", out.String()) }
}

func TestPostsuperOutputLimitTakesPrecedenceOverSuccessfulExit(t *testing.T) {
 path := helperScript(t, "head -c 16384 /dev/zero | tr '\\000' x")
 var out bytes.Buffer
 err := runPostsuperCommand(context.Background(), path, nil, &out)
 if !errors.Is(err, errOutputLimit) {
  t.Fatalf("want output-limit sentinel, got %v", err)
 }
 if out.Len() != 0 { t.Fatalf("oversized command produced success output: %q", out.String()) }
}

func TestPostsuperCancellationKillsDescendantHoldingOutputPipe(t *testing.T) {
 // A child that backgrounds a process with inherited stdout used to keep
 // os/exec waiting for the pipe even after the direct child was killed.
 path := helperScript(t, "sleep 10 & wait")
 ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
 defer cancel()
 var out bytes.Buffer
 started := time.Now()
 err := runPostsuperCommand(ctx, path, nil, &out)
 if !errors.Is(err, context.DeadlineExceeded) {
  t.Fatalf("expected deadline error, got %v", err)
 }
 if time.Since(started) > 3*time.Second {
  t.Fatalf("descendant held output pipe after cancellation: %s", time.Since(started))
 }
 if out.Len() != 0 { t.Fatalf("canceled helper emitted success: %q", out.String()) }
}

func TestPostsuperCancellationWithDescendantOutput(t *testing.T) {
 path := helperScript(t, "sleep 10 & echo 'pending release' >&2; wait")
 ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
 defer cancel()
 var out bytes.Buffer
 err := runPostsuperCommand(ctx, path, nil, &out)
 if !errors.Is(err, context.DeadlineExceeded) {
  t.Fatalf("expected deadline error, got %v", err)
 }
 if out.Len() != 0 { t.Fatalf("canceled helper emitted success: %q", out.String()) }
}


func TestPostsuperOutputLimitTerminatesInfiniteProducer(t *testing.T) {
 // A continuously writing privileged child must be stopped on overflow,
 // without waiting for the eight-second command deadline.
 path := helperScript(t, "while :; do printf '0123456789abcdef0123456789abcdef\\n'; done")
 var out bytes.Buffer
 started := time.Now()
 err := runPostsuperCommand(context.Background(), path, nil, &out)
 if !errors.Is(err, errOutputLimit) {
  t.Fatalf("expected output-limit sentinel, got %v", err)
 }
 if elapsed := time.Since(started); elapsed > 3*time.Second {
  t.Fatalf("output overflow did not terminate child promptly: %s", elapsed)
 }
 if out.Len() != 0 {
  t.Fatalf("overflow produced success output: %q", out.String())
 }
}

func TestPostsuperOutputLimitKillsBackgroundProducer(t *testing.T) {
 // A background process inheriting stderr must not retain the pipe after
 // the output limit has been exceeded by the foreground child.
 path := helperScript(t, "sleep 10 & head -c 16384 /dev/zero | tr '\\000' x >&2")
 var out bytes.Buffer
 started := time.Now()
 err := runPostsuperCommand(context.Background(), path, nil, &out)
 if !errors.Is(err, errOutputLimit) {
  t.Fatalf("expected output-limit sentinel, got %v", err)
 }
 if elapsed := time.Since(started); elapsed > 3*time.Second {
  t.Fatalf("background child retained pipe after overflow: %s", elapsed)
 }
 if out.Len() != 0 { t.Fatal("overflow produced success output") }
}

type failingReleaseSink struct{}
func (failingReleaseSink) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestPostsuperSuccessRequiresResultSink(t *testing.T) {
 path := helperScript(t, "echo 'postsuper: Released: 1 message' >&2")
 err := runPostsuperCommand(context.Background(), path, nil, nil)
 if err == nil || !strings.Contains(err.Error(), "sink is unavailable") {
  t.Fatalf("nil result sink accepted: %v", err)
 }
}

func TestPostsuperResultSinkFailurePropagates(t *testing.T) {
 path := helperScript(t, "echo 'postsuper: Released: 1 message' >&2")
 err := runPostsuperCommand(context.Background(), path, nil, failingReleaseSink{})
 if !errors.Is(err, os.ErrClosed) || !strings.Contains(err.Error(), "reporting failed") {
  t.Fatalf("result sink failure hidden: %v", err)
 }
}

func TestPostsuperResultSinkIsNotUsedOnChildFailure(t *testing.T) {
 path := helperScript(t, "echo 'not found' >&2; exit 7")
 err := runPostsuperCommand(context.Background(), path, nil, failingReleaseSink{})
 if err == nil || !strings.Contains(err.Error(), "not found") || errors.Is(err, os.ErrClosed) {
  t.Fatalf("child failure was hidden by sink: %v", err)
 }
}

type shortReleaseSink struct { writes int }
func (s *shortReleaseSink) Write(p []byte) (int, error) {
 s.writes++
 if len(p) == 0 { return 0, nil }
 return len(p)-1, nil
}

func TestPostsuperNilSinkNeverExecutesPrivilegedAction(t *testing.T) {
 marker := filepath.Join(t.TempDir(), "executed")
 path := helperScript(t, "touch '"+marker+"'; echo released")
 err := runPostsuperCommand(context.Background(), path, []string{"-H", "A123"}, nil)
 if err == nil || !strings.Contains(err.Error(), "sink is unavailable") {
  t.Fatalf("missing sink not rejected: %v", err)
 }
 if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
  t.Fatalf("privileged action ran before validating sink: %v", statErr)
 }
}

func TestPostsuperShortResultWriteIsFailure(t *testing.T) {
 path := helperScript(t, "echo 'postsuper: Released: 1 message' >&2")
 sink := &shortReleaseSink{}
 err := runPostsuperCommand(context.Background(), path, []string{"-H", "A123"}, sink)
 if !errors.Is(err, os.ErrClosed) && !errors.Is(err, io.ErrShortWrite) {
  t.Fatalf("silent short write accepted: %v", err)
 }
 if sink.writes != 1 { t.Fatalf("unexpected sink writes: %d", sink.writes) }
}
