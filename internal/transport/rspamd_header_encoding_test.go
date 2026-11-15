package transport

import (
 "net/http"
 "strings"
 "testing"
)

func TestRspamdHeaderValueBoundaries(t *testing.T) {
 cases := []struct{name, value string; valid bool}{
  {"ASCII", "sender@example.test", true},
  {"UTF8", "müller@example.test", true},
  {"empty", "", true},
  {"maximum", strings.Repeat("x", 64), true},
  {"oversized", strings.Repeat("x", 65), false},
  {"invalid UTF8", string([]byte{0xff, 'x'}), false},
  {"truncated UTF8", string([]byte{0xc3}), false},
  {"NUL", "a\x00b", false},
  {"CR", "a\rb", false},
  {"LF", "a\nb", false},
  {"DEL", "a\x7fb", false},
  {"C1 control", "a\u0085b", false},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   if got := rspamdValidHeaderValue(tc.value,64); got != tc.valid {
    t.Fatalf("valid=%v want %v",got,tc.valid)
   }
  })
 }
}

func TestRspamdNoncanonicalDuplicateHeaders(t *testing.T) {
 for _, name := range []string{"IP","From","Helo","Flags","Compression","Content-Encoding","Deliver-To"} {
  t.Run(name,func(t *testing.T){
   h:=http.Header{name:{"first"}}
   h[strings.ToLower(name)]=[]string{"second"}
   if _,err:=rspamdSingleHeader(h,name,512); err==nil {t.Fatal("ambiguous duplicate accepted")}
  })
 }
}

func TestRspamdInvalidRecipientEncoding(t *testing.T) {
 for _, recipient:=range []string{"x\u0085@example.test",string([]byte{'x',0xff,'@','a'}),"x\x7f@example.test"} {
  h:=make(http.Header)
  h.Add("Rcpt",recipient)
  if _,err:=rspamdReadRequestMetadata(h);err==nil {t.Fatalf("invalid recipient accepted: %q",recipient)}
 }
}

func TestRspamdInvalidIdentityEncoding(t *testing.T) {
 for _, name:=range []string{"From","Helo","IP","Flags","Deliver-To"} {
  h:=make(http.Header)
  h.Set(name,string([]byte{0xff}))
  if _,err:=rspamdReadRequestMetadata(h);err==nil {t.Fatalf("invalid %s accepted",name)}
 }
}
