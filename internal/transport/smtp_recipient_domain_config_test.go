package transport

import "testing"

func TestSMTPFromEnvRecipientDomainPolicy(t *testing.T) {
 t.Setenv("SPAMGATE_SMTP_LISTEN", "127.0.0.1:0")
 t.Setenv("SPAMGATE_SMTP_TRUSTED_CIDRS", "127.0.0.1/32")
 for _, tc := range []struct { name, domains string; valid bool }{
  {"ordinary", "example.com", true},
  {"multiple canonical", "example.com, xn--bcher-kva.example", true},
  {"uppercase normalized", "EXAMPLE.COM", true},
  {"wildcard", "*.example.com", false},
  {"empty label", "example..com", false},
  {"trailing root dot", "example.com.", false},
  {"leading dot", ".example.com", false},
  {"underscore", "example_com", false},
  {"unicode", "bücher.example", false},
  {"path separator", "example.com/path", false},
  {"empty member", "example.com,", false},
  {"single label", "localhost", false},
 } {
  t.Run(tc.name,func(t *testing.T) {
   t.Setenv("SPAMGATE_ALLOWED_RECIPIENT_DOMAINS",tc.domains)
   s,err:=SMTPFromEnv(nil,&Relay{})
   if (err==nil)!=tc.valid {t.Fatalf("SMTPFromEnv(%q) returned %v; valid=%v",tc.domains,err,tc.valid)}
   if tc.valid && (s==nil || len(s.Domains)==0) {t.Fatalf("valid policy returned no domains")}
  })
 }
}
