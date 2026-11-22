package transport

import (
 "net"
 "strings"
 "testing"
)

func TestNativeSMTPBindAddressPreflight(t *testing.T) {
 cases := []struct { address string; allowed bool }{
  {"127.0.0.1:38470", true},
  {"[::1]:38472", true},
  {":38470", true},
  {"0.0.0.0:38470", true},
  {"127.0.0.1:0", false},
  {"127.0.0.1:smtp", false},
  {"127.0.0.1:65536", false},
  {"127.0.0.1:-1", false},
  {"127.0.0.1:38470\n", false},
  {"[fe80::1%eth0]:38470", false},
  {"127.0.0.1", false},
 }
 for _, tc := range cases {
  t.Run(strings.ReplaceAll(tc.address, "/", "_"), func(t *testing.T) {
   err := validateSMTPListenAddress(tc.address)
   if (err == nil) != tc.allowed { t.Fatalf("address %q: error %v; allowed %t", tc.address, err, tc.allowed) }
  })
 }
}

func TestNativeSMTPTrustedNetworkPreflight(t *testing.T) {
 _, ipv4, err := net.ParseCIDR("127.0.0.0/8")
 if err != nil { t.Fatal(err) }
 _, ipv6, err := net.ParseCIDR("2001:db8::/32")
 if err != nil { t.Fatal(err) }
 cases := []struct { name string; network *net.IPNet; allowed bool }{
  {"IPv4", ipv4, true},
  {"IPv6", ipv6, true},
  {"nil", nil, false},
  {"noncontiguous", &net.IPNet{IP: net.IPv4(127,0,0,0).To4(), Mask: net.IPMask{255,0,255,0}}, false},
  {"short mask", &net.IPNet{IP: net.IPv4(127,0,0,0).To4(), Mask: net.IPMask{255}}, false},
  {"host bits", &net.IPNet{IP: net.IPv4(127,0,0,1).To4(), Mask: net.CIDRMask(8,32)}, false},
  {"invalid IP", &net.IPNet{IP: net.IP{1,2}, Mask: net.CIDRMask(24,32)}, false},
  {"family mismatch", &net.IPNet{IP: net.IPv4(127,0,0,0).To4(), Mask: net.CIDRMask(32,128)}, false},
 }
 for _, tc := range cases {
  t.Run(tc.name,func(t *testing.T) {
   err := validateSMTPTrustedCIDR(tc.network)
   if (err == nil) != tc.allowed { t.Fatalf("network %v: error %v; allowed %t", tc.network, err, tc.allowed) }
  })
 }
}

func TestNativeSMTPPreflightDomainIdentity(t *testing.T) {
 if !isASCIIDomain("EXAMPLE.COM") { t.Fatal("ASCII uppercase domain rejected") }
 if isASCIIDomain("K.example") { t.Fatal("Unicode lookalike admitted") }
}
