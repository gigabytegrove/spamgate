package main

import (
 "bytes"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestJSONQualificationDecision(t *testing.T) {
 dir := filepath.Join(t.TempDir(), "delivery-queue")
 if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
 check := func(wantPassed bool, wantFailures int, args ...string) []string {
  t.Helper()
  var out, errs bytes.Buffer
  code := run(append([]string{"-dir",dir,"-json"},args...), &out, &errs)
  var report struct {
   GatePassed *bool `json:"gate_passed"`
   GateFailures []string `json:"gate_failures"`
   Findings []json.RawMessage `json:"findings"`
  }
  if err := json.Unmarshal(out.Bytes(), &report); err != nil { t.Fatalf("invalid JSON: %v; %s",err,out.String()) }
  if report.GatePassed == nil || *report.GatePassed != wantPassed { t.Fatalf("unexpected decision: %+v",report) }
  if len(report.GateFailures) != wantFailures { t.Fatalf("unexpected failures: %+v",report) }
  if wantPassed && code != 0 || !wantPassed && code != 1 { t.Fatalf("unexpected exit %d: %s",code,errs.String()) }
  return report.GateFailures
 }
 check(true,0,"-max-pending=0")
 if err := os.WriteFile(filepath.Join(dir,".pending-interrupted"),[]byte("invalid"),0600); err != nil { t.Fatal(err) }
 failures := check(false,2,"-max-pending=0")
 if failures[0] != "pending=1 exceeds max-pending=0" || failures[1] != "integrity:unreadable_record=1" {
  t.Fatalf("unexpected combined failures: %v",failures)
 }
 failures = check(false,1)
 if !strings.HasPrefix(failures[0],"integrity:") { t.Fatalf("missing integrity reason: %v",failures) }
}
