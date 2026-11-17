//go:build linux

package main

import (
 "errors"
 "fmt"
 "testing"
)

func TestReleaseExitCodeFailClosed(t *testing.T) {
 cases := []struct {
  name string
  err error
  want int
 }{
  {"success", nil, 0},
  {"preflight refusal", errors.New("queue ID invalid"), releasePreflightExitCode},
  {"indeterminate direct", errReleaseOutcomeUnknown, releaseOutcomeUnknownExitCode},
  {"indeterminate wrapped", fmt.Errorf("reporting failed: %w", errReleaseOutcomeUnknown), releaseOutcomeUnknownExitCode},
  {"indeterminate joined", errors.Join(errReleaseOutcomeUnknown, errOutputLimit), releaseOutcomeUnknownExitCode},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   if got := releaseExitCode(tc.err); got != tc.want {
    t.Fatalf("releaseExitCode(%v) = %d, want %d", tc.err, got, tc.want)
   }
  })
 }
 if releaseOutcomeUnknownExitCode == releasePreflightExitCode {
  t.Fatal("ambiguous and preflight outcomes must have distinct process exit codes")
 }
}

func TestReleaseFailureExitCodeNeverSignalsSuccess(t *testing.T) {
 for _, err := range []error{errors.New("refused"), errReleaseOutcomeUnknown, errors.Join(errReleaseOutcomeUnknown, errOutputLimit)} {
  if releaseExitCode(err) == 0 { t.Fatalf("failure unexpectedly returned success: %v", err) }
 }
}
