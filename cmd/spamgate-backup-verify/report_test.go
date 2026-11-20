package main

import (
 "bytes"
 "encoding/json"
 "errors"
 "strings"
 "testing"
)

type failedWriter struct{}
func (failedWriter) Write([]byte)(int,error){return 0,errors.New("write failed")}

func TestBackupResultJSON(t *testing.T) {
 for _, op := range []string{"verify","restore"} {
  var out bytes.Buffer
  if err:=writeBackupResult(&out,"json",op,7,1024);err!=nil{t.Fatal(err)}
  var result struct {Operation string `json:"operation"`; Status string `json:"status"`; Files int64 `json:"files"`; Bytes int64 `json:"bytes"`; MailServicesChanged bool `json:"mail_services_changed"`}
  if err:=json.Unmarshal(out.Bytes(),&result);err!=nil{t.Fatal(err)}
  if result.Operation!=op || result.Status!="success" || result.Files!=7 || result.Bytes!=1024 || result.MailServicesChanged {t.Fatalf("invalid result: %+v",result)}
  if strings.Contains(out.String(),"/opt/"){t.Fatal("path leaked")}
 }
}
func TestBackupResultText(t *testing.T) {
 var out bytes.Buffer
 if err:=writeBackupResult(&out,"text","verify",0,0);err!=nil{t.Fatal(err)}
 if got,want:=out.String(),"verify successful: 0 files, 0 bytes; no mail services changed\n";got!=want{t.Fatalf("got %q want %q",got,want)}
}
func TestBackupResultInvalidNoOutput(t *testing.T) {
 for _,tc:=range []struct{format,operation string;files,bytes int64}{{"xml","verify",1,1},{"json","remove",1,1},{"json","verify",-1,1},{"json","verify",1,-1}} {
  var out bytes.Buffer
  if err:=writeBackupResult(&out,tc.format,tc.operation,tc.files,tc.bytes);err==nil{t.Fatalf("accepted %+v",tc)}
  if out.Len()!=0{t.Fatalf("partial output for %+v",tc)}
 }
 if err:=writeBackupResult(nil,"json","verify",1,1);err==nil{t.Fatal("nil writer accepted")}
}
func TestBackupResultWriteError(t *testing.T) {
 for _,format:=range []string{"json","text"}{if err:=writeBackupResult(failedWriter{},format,"verify",1,2);err==nil{t.Fatalf("%s ignored write error",format)}}
}
