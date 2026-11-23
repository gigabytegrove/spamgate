package transport

import (
 "strings"
 "testing"
)

func TestValidateRelayEndpoint(t *testing.T) {
 valid := map[string]string{
  "localhost:25": "localhost",
  "mail.example.org:587": "mail.example.org",
  "MAIL.EXAMPLE.ORG:465": "MAIL.EXAMPLE.ORG",
  "127.0.0.1:2525": "127.0.0.1",
  "[::1]:25": "::1",
  "[2001:db8::1]:587": "2001:db8::1",
 }
 for endpoint, want := range valid {
  t.Run("valid_"+endpoint, func(t *testing.T) {
   got, err := validateRelayEndpoint(endpoint)
   if err != nil || got != want { t.Fatalf("host=%q error=%v, want %q", got, err, want) }
  })
 }
 invalid := []string{
  "", "mail.example.org", ":25", "mail.example.org:", "mail.example.org:0",
  "mail.example.org:65536", "mail.example.org:smtp", "mail.example.org:-1",
  "mail.example.org:25 ", "mail.example.org:25\n", "mail.example.org:25/tcp",
  "bad_host.example:25", "mail..example:25", "-mail.example:25",
  "mail-.example:25", ".example:25", "example.:25", "999.999.999.999:25",
  "[fe80::1%eth0]:25", "[invalid]:25", "user@mail.example:25",
  "mail.example.org:9999999999999999999999999999",
  strings.Repeat("a", 64)+".example:25",
  strings.Repeat("a", 250)+".com:25",
  "K.example:25",
 }
 for _, endpoint := range invalid {
  t.Run("invalid_"+endpoint, func(t *testing.T) {
   if host, err := validateRelayEndpoint(endpoint); err == nil {
    t.Fatalf("accepted unsafe endpoint %q as %q", endpoint, host)
   }
  })
 }
}

func TestRelayFromEnvRejectsInvalidEndpoint(t *testing.T) {
 t.Setenv("SPAMGATE_RELAY_ADDRESS", "mail.example.org:smtp")
 t.Setenv("SPAMGATE_RELAY_TLS", "required")
 if relay, err := RelayFromEnv(); err == nil || relay != nil {
  t.Fatalf("accepted nonnumeric port: relay=%v err=%v", relay, err)
 }
}
