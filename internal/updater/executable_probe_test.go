//go:build linux

package updater

import (
 "errors"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func writeProbeFixture(t *testing.T, script string) string {
 t.Helper()
 path := filepath.Join(t.TempDir(), "worker")
 if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0700); err != nil { t.Fatal(err) }
 return path
}

func TestExecutableProbeBoundsOutputAndPreservesExit(t *testing.T) {
 t.Run("normal", func(t *testing.T) {
  path := writeProbeFixture(t, "printf '0.6.0-alpha.11\\n'")
  value, err := probeExecutableFlag(path, "-version")
  if err != nil || strings.TrimSpace(value) != "0.6.0-alpha.11" { t.Fatalf("probe = %q, %v", value, err) }
 })
 t.Run("normal nonzero", func(t *testing.T) {
  path := writeProbeFixture(t, "exit 2")
  value, err := probeExecutableFlag(path, "-build-version")
  var exit *exec.ExitError
  if value != "" || !errors.As(err, &exit) || exit.ExitCode() != 2 { t.Fatalf("nonzero exit = %q, %v", value, err) }
 })
 t.Run("oversized", func(t *testing.T) {
  path := writeProbeFixture(t, "head -c 100000 /dev/zero | tr '\\000' 'x'")
  _, err := probeExecutableFlag(path, "-version")
  if err == nil || !strings.Contains(err.Error(), "exceeded") { t.Fatalf("oversized output accepted: %v", err) }
 })
 t.Run("timeout", func(t *testing.T) {
  if testing.Short() { t.Skip("five-second timeout integration") }
  path := writeProbeFixture(t, "sleep 10")
  started := time.Now()
  _, err := probeExecutableFlag(path, "-build-version")
  if err == nil || !strings.Contains(err.Error(), "timed out") { t.Fatalf("stalled probe accepted: %v", err) }
  if time.Since(started) > 8*time.Second { t.Fatalf("probe exceeded bounded runtime: %v", time.Since(started)) }
 })
}

func TestExecutableBuildVersionFailsClosedOnAmbiguousProbes(t *testing.T) {
 cases := []struct { name, script, want string; reject bool }{
  {"silent unsupported flag", "exit 2", "unversioned", false},
  {"silent successful legacy", "exit 0", "unversioned", false},
  {"valid numbered build", "printf '20261101-12\\n'", "20261101-12", false},
  {"explicit malformed build", "printf 'malformed\\n'", "", true},
  {"nonzero contradictory stdout", "printf '20261101-12\\n'; exit 2", "", true},
  {"oversized identity", "head -c 100000 /dev/zero | tr '\\000' 'x'", "", true},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   got, err := executableBuildVersion(writeProbeFixture(t, tc.script))
   if (err != nil) != tc.reject || (!tc.reject && got != tc.want) {
    t.Fatalf("build identity = %q, %v; want %q reject=%v", got, err, tc.want, tc.reject)
   }
  })
 }
 t.Run("source version must also be bounded", func(t *testing.T) {
  _, err := executableVersion(writeProbeFixture(t, "head -c 100000 /dev/zero | tr '\\000' 'x'"))
  if err == nil || !strings.Contains(err.Error(), "exceeded") { t.Fatalf("oversized source version accepted: %v", err) }
 })
 t.Run("nonexistent candidate cannot masquerade as legacy", func(t *testing.T) {
  _, err := executableBuildVersion(filepath.Join(t.TempDir(), "missing"))
  if err == nil { t.Fatal("missing executable accepted as legacy") }
 })
}
