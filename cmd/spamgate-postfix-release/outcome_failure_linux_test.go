//go:build linux

package main

import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func writeReconciliationFixture(t *testing.T, body string) string {
 t.Helper()
 path := filepath.Join(t.TempDir(), "fake-postsuper")
 if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil { t.Fatal(err) }
 return path
}

func TestReleaseOutcomeUnknownAfterChildFailure(t *testing.T) {
 path := writeReconciliationFixture(t, "echo 'recipient=private@example.invalid' >&2; exit 7")
 var report strings.Builder
 err := runPostsuperCommand(context.Background(), path, []string{"-H", "ABC123"}, &report)
 if !errors.Is(err, errReleaseOutcomeUnknown) { t.Fatalf("child failure must require reconciliation: %v", err) }
 if strings.Contains(err.Error(), "private@example.invalid") { t.Fatalf("sensitive child output leaked: %v", err) }
 if report.Len() != 0 { t.Fatalf("failed command must not produce success report: %q", report.String()) }
}

func TestReleaseOutcomeUnknownAfterOutputOverflow(t *testing.T) {
 path := writeReconciliationFixture(t, "head -c 16384 /dev/zero")
 var report strings.Builder
 err := runPostsuperCommand(context.Background(), path, []string{"-H", "ABC123"}, &report)
 if !errors.Is(err, errReleaseOutcomeUnknown) || !errors.Is(err, errOutputLimit) {
  t.Fatalf("output overflow must preserve limit and reconciliation identity: %v", err)
 }
 if report.Len() != 0 { t.Fatalf("overflow must not produce success report: %q", report.String()) }
}

func TestPreExecutionFailuresAreNotIndeterminate(t *testing.T) {
 path := writeReconciliationFixture(t, "exit 0")
 ctx, cancel := context.WithCancel(context.Background())
 cancel()
 for _, tc := range []struct{name string; ctx context.Context; executable string}{
  {"canceled", ctx, path},
  {"missing executable", context.Background(), ""},
 } {
  t.Run(tc.name, func(t *testing.T) {
   var report strings.Builder
   err := runPostsuperCommand(tc.ctx, tc.executable, nil, &report)
   if err == nil || errors.Is(err, errReleaseOutcomeUnknown) { t.Fatalf("pre-execution failure misclassified: %v", err) }
  })
 }
}
