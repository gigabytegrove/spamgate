package spoolaudit

import (
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestAuditReadFailureNeverLeaksUntrustedError(t *testing.T) {
 secret:="private-recipient@example.invalid"
 cases:=[]struct{err error;want string}{
  {errors.New("persisted scan envelope duplicate key "+secret),"invalid persisted scan evidence"},
  {errors.New("invalid or ambiguous spool JSON: duplicate key "+secret),"invalid or ambiguous record JSON"},
  {errors.New("durable envelope sender "+secret),"invalid durable envelope metadata"},
  {errors.New("unexpected error "+secret),"record could not be validated"},
  {os.ErrPermission,"record access denied"},
  {os.ErrNotExist,"record disappeared during audit"},
  {errors.New("mutable state digest mismatch"),"record integrity digest mismatch"},
 }
 for _,tc:=range cases {
  got:=auditReadFailure(tc.err)
  if got!=tc.want||strings.Contains(got,secret){t.Fatalf("got %q, want %q",got,tc.want)}
 }
}

func TestAuditReportDoesNotLeakMaliciousScanJSONKey(t *testing.T) {
 dir:=privateDir(t)
 rec:=fixture(idA)
 // Preserve a valid outer envelope while injecting an attacker-controlled
 // duplicate JSON key inside the optional persisted scan evidence.
 raw,err:=json.Marshal(rec)
 if err!=nil{t.Fatal(err)}
 secret:="private-mailbox@example.invalid"
 injected:=`{"`+secret+`":1,"`+secret+`":2}`
 raw=strings.Replace(string(raw),`"scan":null`,`"scan":`+injected,1)
 // The fixture omits scan entirely when nil; insert before final brace.
 if !strings.Contains(raw,injected) {
  raw=strings.TrimSuffix(raw,"}")+`,"scan":`+injected+"}"
 }
 path:=filepath.Join(dir,idA+".json")
 if err:=os.WriteFile(path,[]byte(raw),0600);err!=nil{t.Fatal(err)}
 report,err:=Audit(dir)
 if err!=nil{t.Fatal(err)}
 if report.UnreadableRecords!=1||!hasCode(report,"unreadable_record"){
  t.Fatalf("expected unreadable record finding: %+v",report)
 }
 encoded,err:=json.Marshal(report)
 if err!=nil{t.Fatal(err)}
 if strings.Contains(string(encoded),secret){t.Fatal("audit report leaked malicious scan key")}
 if !strings.Contains(string(encoded),"invalid or ambiguous record JSON") {
  t.Fatalf("missing actionable sanitized category: %s",encoded)
 }
}
