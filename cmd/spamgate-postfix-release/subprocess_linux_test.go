//go:build linux

package main

import (
 "bytes"
 "context"
 "errors"
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
