package smtpprobe

import (
 "reflect"
 "strings"
 "testing"
)

func TestCapabilitiesEvidenceBoundaries(t *testing.T) {
 cases := []struct {
  name string
  lines []string
  tls bool
  auth []string
 }{
  {"identity starttls", []string{"STARTTLS"}, false, []string{}},
  {"identity auth", []string{"AUTH PLAIN"}, false, []string{}},
  {"normal", []string{"mail.example ESMTP", "STARTTLS", "AUTH PLAIN LOGIN"}, true, []string{"PLAIN","LOGIN"}},
  {"duplicate AUTH advertisements rejected", []string{"host", "auth plain PLAIN login", "AUTH=LOGIN CRAM-MD5"}, false, []string{}},
  {"single AUTH advertisement deduplicated", []string{"host", "AUTH PLAIN plain LOGIN"}, false, []string{"PLAIN","LOGIN"}},
  {"malformed", []string{"host", "STARTTLS unexpected", "AUTH PLAIN=oops bad/token", "AUTH= bad@token"}, false, []string{}},
  {"length bound", []string{"host", "AUTH "+strings.Repeat("X",41)+" PLAIN"}, false, []string{}},
  {"empty", nil, false, []string{}},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   tls,auth:=capabilities(tc.lines)
   if tls!=tc.tls || !reflect.DeepEqual(auth,tc.auth) {t.Fatalf("got tls=%v auth=%q, want tls=%v auth=%q",tls,auth,tc.tls,tc.auth)}
  })
 }
}
