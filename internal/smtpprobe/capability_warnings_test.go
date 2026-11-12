package smtpprobe

import (
 "reflect"
 "testing"
)

func TestCapabilityWarnings(t *testing.T) {
 cases := []struct { name string; lines, want []string }{
  {"identity ignored", []string{"BINARYMIME", "CHUNKING"}, nil},
  {"valid", []string{"mail.example", "CHUNKING", "BINARYMIME", "AUTH PLAIN LOGIN"}, nil},
  {"binary dependency", []string{"mail.example", "BINARYMIME"}, []string{"BINARYMIME_WITHOUT_CHUNKING"}},
  {"malformed starttls", []string{"mail.example", "STARTTLS now"}, []string{"UNEXPECTED_EXTENSION_PARAMETERS"}},
  {"duplicate", []string{"mail.example", "STARTTLS", "STARTTLS"}, []string{"DUPLICATE_EXTENSION"}},
  {"auth empty", []string{"mail.example", "AUTH"}, []string{"EMPTY_AUTH_ADVERTISEMENT"}},
  {"auth invalid", []string{"mail.example", "AUTH bad/token"}, []string{"MALFORMED_AUTH_MECHANISM", "EMPTY_AUTH_ADVERTISEMENT"}},
  {"bad keyword", []string{"mail.example", "BAD_KEY"}, []string{"MALFORMED_EXTENSION_KEYWORD"}},
  {"empty extension", []string{"mail.example", ""}, []string{"EMPTY_EXTENSION_LINE"}},
 }
 for _, tc := range cases {
  t.Run(tc.name,func(t *testing.T) {
   got:=capabilityWarnings(tc.lines)
   if len(got)==0 {got=nil}
   if !reflect.DeepEqual(got,tc.want) {t.Fatalf("got %q want %q",got,tc.want)}
  })
 }
}

func TestCapabilityWarningsDeterministic(t *testing.T) {
 lines:=[]string{"host", "AUTH bad/token", "AUTH", "BINARYMIME"}
 want:=[]string{"MALFORMED_AUTH_MECHANISM", "EMPTY_AUTH_ADVERTISEMENT", "DUPLICATE_EXTENSION", "BINARYMIME_WITHOUT_CHUNKING"}
 for i:=0;i<20;i++ {
  if got:=capabilityWarnings(lines);!reflect.DeepEqual(got,want) {t.Fatalf("iteration %d got %q want %q",i,got,want)}
 }
}
