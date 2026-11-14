package transport

import (
 "strings"
 "testing"
)

func TestValidSMTPRecipientDomain(t *testing.T) {
 cases := []struct { domain string; want bool }{
  {"example.com", true},
  {"mail.example.com", true},
  {"xn--bcher-kva.example", true},
  {"a-b.example", true},
  {"example", false},
  {"", false},
  {".example.com", false},
  {"example.com.", false},
  {"example..com", false},
  {"*.example.com", false},
  {"example_com", false},
  {"example.com:25", false},
  {"example.com/path", false},
  {"example.com\\evil", false},
  {"example.com\n", false},
  {"bücher.example", false},
  {"-bad.example", false},
  {"bad-.example", false},
  {"a." + strings.Repeat("b",64) + ".com", false},
  {strings.Repeat("a", 251)+".com", false},
  {"EXAMPLE.COM", false},
 }
 for _, tc := range cases {
  t.Run(tc.domain,func(t *testing.T) {
   if got := validSMTPRecipientDomain(tc.domain); got != tc.want {
    t.Fatalf("validSMTPRecipientDomain(%q) = %v; want %v",tc.domain,got,tc.want)
   }
  })
 }
}

func TestAllowedRecipientExactDomainBoundary(t *testing.T) {
 s := &SMTP{Domains: []string{"example.com","xn--bcher-kva.example"}}
 for _, tc := range []struct { addr string; want bool }{
  {"user@example.com",true},
  {"user@EXAMPLE.COM",true},
  {"user@xn--bcher-kva.example",true},
  {"user@sub.example.com",false},
  {"user@notexample.com",false},
  {"user@example.com.evil",false},
  {"user@example.com.",false},
  {"user@bücher.example",false},
  {"user@other.test",false},
 } {
  if got := s.allowedRecipient(tc.addr); got != tc.want {
   t.Errorf("allowedRecipient(%q) = %v; want %v",tc.addr,got,tc.want)
  }
 }
}
