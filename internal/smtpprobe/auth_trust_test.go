package smtpprobe

import (
 "reflect"
 "testing"
)

func TestAUTHTrustRejectsAmbiguousAdvertisements(t *testing.T) {
 cases := []struct {
  name string
  lines []string
  want []string
 }{
  {"valid",[]string{"mx.example","AUTH PLAIN LOGIN"},[]string{"PLAIN","LOGIN"}},
  {"legacy",[]string{"mx.example","AUTH=PLAIN LOGIN"},[]string{"PLAIN","LOGIN"}},
  {"case insensitive",[]string{"mx.example","auth plain login"},[]string{"PLAIN","LOGIN"}},
  {"identity only",[]string{"AUTH PLAIN"},[]string{}},
  {"empty",[]string{"mx.example","AUTH"},[]string{}},
  {"empty legacy",[]string{"mx.example","AUTH="},[]string{}},
  {"duplicate",[]string{"mx.example","AUTH PLAIN","AUTH LOGIN"},[]string{}},
  {"mixed forms",[]string{"mx.example","AUTH=PLAIN","AUTH LOGIN"},[]string{}},
  {"malformed with valid",[]string{"mx.example","AUTH PLAIN bad/mech"},[]string{}},
  {"overlong",[]string{"mx.example","AUTH PLAIN ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNO"},[]string{}},
  {"valid with unrelated extension",[]string{"mx.example","SIZE 1024","AUTH PLAIN","PIPELINING"},[]string{"PLAIN"}},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   _,got:=capabilities(tc.lines)
   if !reflect.DeepEqual(got,tc.want) {
    t.Fatalf("capabilities(%q) auth=%q want=%q",tc.lines,got,tc.want)
   }
  })
 }
}

func TestAUTHTrustIndependentOfSTARTTLS(t *testing.T) {
 lines:=[]string{"mx.example","STARTTLS","AUTH PLAIN","AUTH LOGIN"}
 tls,auth:=capabilities(lines)
 if !tls { t.Fatal("valid STARTTLS must remain usable despite AUTH ambiguity") }
 if len(auth)!=0 { t.Fatalf("ambiguous AUTH accepted: %v",auth) }
}
