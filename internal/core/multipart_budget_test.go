package core

import (
 "bytes"
 "fmt"
 "strings"
 "testing"
)

// This regression protects the streaming limit on individual multipart
// sections. In particular, 5<<20+1 is parsed as 5<<(20+1), not (5<<20)+1.
func TestMultipartAttachmentReadBudget(t *testing.T) {
 const boundary = "spamgate-budget"
 for _, tc := range []struct{name string; size int; over bool}{
  {"at limit",5<<20,false},
  {"one byte over",(5<<20)+1,true},
  {"six mebibytes",6<<20,true},
 } {
  t.Run(tc.name,func(t *testing.T){
   var raw bytes.Buffer
   fmt.Fprintf(&raw,"From: a@example.invalid\r\nTo: b@example.invalid\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=%q\r\n\r\n--%s\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"payload.bin\"\r\n\r\n",boundary,boundary)
   raw.Write(bytes.Repeat([]byte{'A'},tc.size))
   fmt.Fprintf(&raw,"\r\n--%s--\r\n",boundary)
   findings,err:=InspectMIMEAttachments(raw.Bytes())
   if err!=nil {t.Fatal(err)}
   limited:=false
   for _,f:=range findings {if f.Symbol=="MIME_LIMIT" {limited=true}}
   if limited!=tc.over {t.Fatalf("size=%d want MIME_LIMIT=%v findings=%+v",tc.size,tc.over,findings)}
  })
 }
}

func TestMultipartOversizeDoesNotHideFollowingSafePart(t *testing.T) {
 boundary:="spamgate-following"
 var raw bytes.Buffer
 fmt.Fprintf(&raw,"From: a@example.invalid\r\nTo: b@example.invalid\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=%q\r\n\r\n--%s\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"oversized.bin\"\r\n\r\n",boundary,boundary)
 raw.Write(bytes.Repeat([]byte{'B'},(5<<20)+1))
 fmt.Fprintf(&raw,"\r\n--%s\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"payload.exe\"\r\n\r\nMZpayload\r\n--%s--\r\n",boundary,boundary)
 findings,err:=InspectMIMEAttachments(raw.Bytes())
 if err!=nil {t.Fatal(err)}
 var limited,executable bool
 for _,f:=range findings {
  limited=limited||f.Symbol=="MIME_LIMIT"
  executable=executable||f.Symbol=="ATTACHMENT_EXECUTABLE_CONTENT"
 }
 if !limited||!executable {t.Fatalf("expected limit and subsequent executable evidence: %+v",findings)}
 if strings.Contains(fmt.Sprint(findings),"oversized.bin") {t.Fatal("oversized attachment should not be decoded")}
}
