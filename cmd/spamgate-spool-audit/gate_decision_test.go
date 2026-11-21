package main

import (
 "bytes"
 "encoding/json"
 "os"
 "path/filepath"
 "testing"
)

func TestJSONQualificationDecision(t *testing.T) {
 dir := filepath.Join(t.TempDir(), "delivery-queue")
 if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
 check := func(wantPassed bool, wantFailures int, args ...string) {
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
 }
 check(true,0,"-max-pending=0")
 if err := os.WriteFile(filepath.Join(dir,".pending-interrupted"),[]byte("invalid"),0600); err != nil { t.Fatal(err) }
 check(false,1,"-max-pending=0")
 check(false,0)
}
