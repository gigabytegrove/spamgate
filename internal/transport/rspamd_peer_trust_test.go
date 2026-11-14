package transport

import (
    "net"
    "testing"
)

func TestRspamdPeerTrustedAddressFamilyBoundary(t *testing.T) {
    _, ipv6, err := net.ParseCIDR("192.0.2.0/24")
    if err != nil { t.Fatal(err) }
    _, v6, err := net.ParseCIDR("2001:db8::/64")
    if err != nil { t.Fatal(err) }
    for _, tc := range []struct { name, remote string; want bool }{
        {"IPv4 allowed", "192.0.2.50:1234", true},
        {"IPv4 denied", "192.0.3.50:1234", false},
        {"IPv6 allowed", "[2001:db8::50]:1234", true},
        {"IPv6 denied", "[2001:db9::50]:1234", false},
        {"mapped IPv4 denied", "[::ffff:192.0.2.50]:1234", false},
        {"mapped hexadecimal denied", "[::ffff:c000:232]:1234", false},
        {"zone denied", "[fe80::1%eth0]:1234", false},
        {"no port denied", "192.0.2.50", false},
        {"hostname denied", "localhost:1234", false},
        {"empty denied", "", false},
    } {
        t.Run(tc.name, func(t *testing.T) {
            if got := rspamdPeerTrusted(tc.remote, []*net.IPNet{ipv6, v6}); got != tc.want {
                t.Fatalf("peer %q trusted=%v want=%v", tc.remote, got, tc.want)
            }
        })
    }
    if rspamdPeerTrusted("192.0.2.50:1234", nil) { t.Fatal("empty ACL trusted peer") }
    if rspamdPeerTrusted("192.0.2.50:1234", []*net.IPNet{nil}) { t.Fatal("nil ACL entry trusted peer") }
}
