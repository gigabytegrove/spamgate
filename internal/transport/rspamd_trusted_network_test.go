package transport

import (
 "net"
 "testing"
)

func TestRspamdTrustedNetworksCanonicalBoundaries(t *testing.T) {
 tests := []struct {
  name string
  raw string
  valid bool
  allowed string
  denied string
 }{
  {"default loopbacks", "127.0.0.1/32,::1/128", true, "127.0.0.1", "192.0.2.1"},
  {"IPv4 host", "192.0.2.5", true, "192.0.2.5", "192.0.2.6"},
  {"IPv6 host", "2001:db8::5", true, "2001:db8::5", "2001:db8::6"},
  {"IPv4 network", "192.0.2.0/24", true, "192.0.2.99", "192.0.3.1"},
  {"IPv6 network", "2001:db8::/64", true, "2001:db8::99", "2001:db9::1"},
  {"host bits widened", "192.0.2.5/24", false, "", ""},
  {"IPv6 host bits widened", "2001:db8::1/64", false, "", ""},
  {"mapped IPv6 host", "::ffff:192.0.2.5", false, "", ""},
  {"mapped IPv6 prefix", "::ffff:192.0.2.0/120", false, "", ""},
  {"embedded IPv4", "2001:db8::192.0.2.5/128", false, "", ""},
  {"zone", "fe80::1%eth0", false, "", ""},
  {"empty", "", false, "", ""},
  {"whitespace only", "  ", false, "", ""},
  {"empty middle entry", "127.0.0.1,,::1", false, "", ""},
  {"trailing comma", "127.0.0.1,", false, "", ""},
  {"leading comma", ",127.0.0.1", false, "", ""},
  {"duplicate", "127.0.0.1,127.0.0.1/32", false, "", ""},
  {"invalid prefix", "192.0.2.0/33", false, "", ""},
  {"malformed host", "192.0.2.999", false, "", ""},
  {"noncanonical IPv4", "010.0.0.1", false, "", ""},
 }
 for _, tt := range tests {
  t.Run(tt.name, func(t *testing.T) {
   networks, err := parseTrustedCIDRs(tt.raw)
   if (err == nil) != tt.valid { t.Fatalf("networks=%v err=%v valid=%v", networks, err, tt.valid) }
   if !tt.valid { return }
   contains := func(address string) bool {
    ip := net.ParseIP(address)
    for _, n := range networks { if n.Contains(ip) { return true } }
    return false
   }
   if !contains(tt.allowed) { t.Errorf("expected %s to be trusted", tt.allowed) }
   if contains(tt.denied) { t.Errorf("unexpected trust of %s", tt.denied) }
  })
 }
}

func TestRspamdTrustedNetworkEntryBudget(t *testing.T) {
 raw := ""
 for i := 0; i < 129; i++ {
  if i > 0 { raw += "," }
  raw += "127.0.0.1/32"
 }
 if _, err := parseTrustedCIDRs(raw); err == nil {
  t.Fatal("oversized ACL accepted")
 }
}
