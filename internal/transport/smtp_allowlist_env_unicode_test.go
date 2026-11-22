package transport

import (
 "strings"
 "testing"
)

// Environment policy is an authorization boundary: reject non-ASCII before
// case folding, including Unicode characters that fold into ASCII.
func TestSMTPFromEnvRejectsUnicodeAllowlist(t *testing.T) {
 t.Setenv("SPAMGATE_SMTP_LISTEN", "127.0.0.1:2525")
 t.Setenv("SPAMGATE_SMTP_TRUSTED_CIDRS", "127.0.0.1/32")
 relay := &Relay{Address: "127.0.0.1:2526", TLSMode: "none"}
 cases := []struct{
  name string
  domains string
  valid bool
 }{
  {"ordinary lowercase", "example.com", true},
  {"ordinary uppercase", "EXAMPLE.COM", true},
  {"mixed case", "Example.COM", true},
  {"unicode kelvin", "K.example", false},
  {"unicode kelvin embedded", "EXAMPLE.KOM", false},
  {"unicode dotted I", "İ.example", false},
  {"unicode fullwidth", "ｅxample.com", false},
  {"unicode after comma", "example.com,K.example", false},
  {"empty list element", "example.com,", false},
  {"whitespace", " Example.COM ", true},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   t.Setenv("SPAMGATE_ALLOWED_RECIPIENT_DOMAINS", tc.domains)
   smtp, err := SMTPFromEnv(nil, relay)
   if (err == nil) != tc.valid {
    t.Fatalf("domains %q: err=%v; expected valid=%v", tc.domains, err, tc.valid)
   }
   if tc.valid {
    if smtp == nil || len(smtp.Domains) != 1 {
     t.Fatalf("expected one configured domain, got %#v", smtp)
    }
    if smtp.Domains[0] != strings.ToLower(strings.TrimSpace(tc.domains)) {
     t.Fatalf("unexpected canonical domain: %q", smtp.Domains[0])
    }
   }
  })
 }
}

func TestSMTPFromEnvInvalidDomainNeverEnablesListener(t *testing.T) {
 t.Setenv("SPAMGATE_SMTP_LISTEN", "127.0.0.1:2525")
 t.Setenv("SPAMGATE_SMTP_TRUSTED_CIDRS", "127.0.0.1/32")
 t.Setenv("SPAMGATE_ALLOWED_RECIPIENT_DOMAINS", "K.example")
 smtp, err := SMTPFromEnv(nil, &Relay{Address: "127.0.0.1:2526", TLSMode: "none"})
 if err == nil || smtp != nil {
  t.Fatalf("unsafe domain configuration must fail closed: smtp=%v err=%v", smtp, err)
 }
}
