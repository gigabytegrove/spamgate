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

func TestAuditReadFailureRejectsCategorySpoofing(t *testing.T) {
 cases:=[]struct{name string;err error;want string}{
  {"keyword embedded in hostile error",errors.New("unknown key \"invalid or ambiguous spool JSON\""),"record could not be validated"},
  {"digest keyword embedded in hostile error",errors.New("untrusted value: mutable state digest mismatch"),"record could not be validated"},
  {"invalid longer prefix",errors.New("invalid spool JSONish diagnostic"),"record could not be validated"},
  {"valid bounded JSON category",errors.New("invalid spool JSON: unexpected token"),"invalid or ambiguous record JSON"},
  {"valid scan category",errors.New("persisted scan envelope duplicate key \"mailbox@example.invalid\""),"invalid persisted scan evidence"},
  {"valid durable timestamp category",errors.New("invalid durable timestamp: created"),"invalid durable timestamp metadata"},
  {"valid state category",errors.New("invalid durable state: attempts"),"invalid durable delivery-state metadata"},
  {"valid envelope category",errors.New("invalid durable envelope: sender"),"invalid durable envelope metadata"},
  {"known path race",errors.New("spool record changed during read"),"record changed during audit; retry read-only inspection"},
  {"known metadata",errors.New("unsafe spool metadata: permissions"),"unsafe record file metadata"},
  {"known size",errors.New("not a bounded regular spool record"),"record is not a bounded regular file"},
  {"nil",nil,"record validation failed"},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   if got:=auditReadFailure(tc.err);got!=tc.want {t.Fatalf("got %q want %q",got,tc.want)}
  })
 }
}
