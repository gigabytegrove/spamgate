package transport

import (
 "net"
 "testing"
)

// Regression: network trust is an access-control boundary, not a convenience
// parser. An ambiguous or broadened CIDR must fail closed.
func TestSMTPTrustedCIDRNetipBoundaries(t *testing.T) {
 cases := []struct{ cidr string; valid bool }{
  {"192.0.2.0/24", true},
  {"192.0.2.5/32", true},
  {"192.0.2.5/24", false},
  {"192.0.2.1/0", false},
  {"0.0.0.0/0", true},
  {"2001:db8::/64", true},
  {"2001:db8::5/128", true},
  {"2001:db8::5/64", false},
  {"::/0", true},
  {"::ffff:c000:200/120", false},
  {"::ffff:192.0.2.0/120", false},
  {"::192.0.2.5/128", false},
  {"2001:db8::192.0.2.5/128", false},
  {"192.0.2.0/33", false},
  {"192.0.2.0/24/24", false},
  {"192.0.2.0/24 ", false},
  {"192.0.2.0/24\n", false},
  {"192.0.2.0/-1", false},
  {"192.0.2.0/024", false},
  {"192.0.2.0/24\x00", false},
  {"", false},
 }
 for _, tc := range cases {
  t.Run(tc.cidr, func(t *testing.T) {
   network, err := parseSMTPTrustedNetwork(tc.cidr)
   if (err == nil) != tc.valid {
    t.Fatalf("CIDR %q network=%v err=%v expected valid=%v", tc.cidr, network, err, tc.valid)
   }
  })
 }
}

func TestSMTPTrustedCIDRNetworkMembership(t *testing.T) {
 cases := []struct{
  cidr, inside, outside string
 }{
  {"192.0.2.0/24", "192.0.2.255", "192.0.3.1"},
  {"192.0.2.5/32", "192.0.2.5", "192.0.2.6"},
  {"2001:db8::/64", "2001:db8::ffff", "2001:db8:0:1::1"},
  {"2001:db8::5/128", "2001:db8::5", "2001:db8::6"},
 }
 for _, tc := range cases {
  t.Run(tc.cidr, func(t *testing.T) {
   n, err := parseSMTPTrustedNetwork(tc.cidr)
   if err != nil { t.Fatal(err) }
   if !n.Contains(net.ParseIP(tc.inside)) { t.Fatalf("%s must contain %s", tc.cidr, tc.inside) }
   if n.Contains(net.ParseIP(tc.outside)) { t.Fatalf("%s must exclude %s", tc.cidr, tc.outside) }
  })
 }
}
