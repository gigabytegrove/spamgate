package transport

import "testing"

func TestRspamdClientIP(t *testing.T) {
 for _, tc := range []struct{name, raw, want string; ok bool}{
  {"absent", "", "", true},
  {"ipv4", "192.0.2.5", "192.0.2.5", true},
  {"ipv6", "2001:db8::5", "2001:db8::5", true},
  {"canonicalize ipv6", "2001:0db8:0:0:0:0:0:5", "2001:db8::5", true},
  {"mapped ipv4", "::ffff:192.0.2.5", "", false},
  {"mapped hex", "::ffff:c000:205", "", false},
  {"zone", "fe80::1%eth0", "", false},
  {"bracketed", "[2001:db8::5]", "", false},
  {"hostport", "192.0.2.5:25", "", false},
  {"whitespace", " 192.0.2.5", "", false},
  {"trailing whitespace", "192.0.2.5 ", "", false},
  {"hostname", "mail.example", "", false},
  {"invalid ipv4", "192.0.2.999", "", false},
  {"ipv4 leading zero", "192.0.2.005", "", false},
 } {
  t.Run(tc.name,func(t *testing.T){
   got,ok:=rspamdClientIP(tc.raw)
   if got!=tc.want || ok!=tc.ok { t.Fatalf("input=%q got=(%q,%v) want=(%q,%v)",tc.raw,got,ok,tc.want,tc.ok) }
  })
 }
}
