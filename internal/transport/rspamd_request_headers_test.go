package transport

import (
 "net/http"
 "strings"
 "testing"
)

func TestRspamdRequestMetadata(t *testing.T) {
 cases := []struct {name string; mutate func(http.Header); wantError bool}{
  {"empty accepted", func(http.Header){}, false},
  {"normal multi recipient", func(h http.Header){h.Add("Rcpt","<a@example.test>");h.Add("Rcpt","<b@example.test>");h.Set("From","<sender@example.test>");h.Set("IP","192.0.2.1")}, false},
  {"duplicate IP denied",func(h http.Header){h.Add("IP","192.0.2.1");h.Add("IP","198.51.100.2")},true},
  {"duplicate From denied",func(h http.Header){h.Add("From","a@example.test");h.Add("From","b@example.test")},true},
  {"duplicate Helo denied",func(h http.Header){h.Add("Helo","a.test");h.Add("Helo","b.test")},true},
  {"duplicate Flags denied",func(h http.Header){h.Add("Flags","no_log");h.Add("Flags","pass_all")},true},
  {"duplicate Deliver-To denied",func(h http.Header){h.Add("Deliver-To","a@test");h.Add("Deliver-To","b@test")},true},
  {"duplicate Compression denied",func(h http.Header){h.Add("Compression","none");h.Add("Compression","zstd")},true},
  {"duplicate Content-Encoding denied",func(h http.Header){h.Add("Content-Encoding","identity");h.Add("Content-Encoding","zstd")},true},
  {"oversized IP denied",func(h http.Header){h.Set("IP",strings.Repeat("x",65))},true},
  {"oversized sender denied",func(h http.Header){h.Set("From",strings.Repeat("x",513))},true},
  {"control in Helo denied",func(h http.Header){h.Set("Helo","hello\x00world")},true},
  {"control in recipient denied",func(h http.Header){h.Add("Rcpt","x\x00@y")},true},
  {"empty recipient denied",func(h http.Header){h.Add("Rcpt","")},true},
  {"too many recipients denied",func(h http.Header){for i:=0;i<101;i++ {h.Add("Rcpt","a@example.test")}},true},
  {"100 recipients accepted",func(h http.Header){for i:=0;i<100;i++ {h.Add("Rcpt","a@example.test")}},false},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){h:=make(http.Header);tc.mutate(h);m,err:=rspamdReadRequestMetadata(h);if (err!=nil)!=tc.wantError {t.Fatalf("err=%v wantError=%v metadata=%+v",err,tc.wantError,m)};if tc.name=="normal multi recipient" && (len(m.Recipients)!=2 || m.Sender!="sender@example.test") {t.Fatalf("unexpected metadata: %+v",m)}})}
}
