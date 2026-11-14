package transport

import (
    "net"
    "net/netip"
)

// rspamdPeerTrusted evaluates the socket peer, never forwarded HTTP headers.
// Reject mapped IPv6 and zone-qualified addresses rather than allowing net.IP
// normalization to cross an IPv4 trust boundary.
func rspamdPeerTrusted(remote string, trusted []*net.IPNet) bool {
    host, _, err := net.SplitHostPort(remote)
    if err != nil { return false }
    addr, err := netip.ParseAddr(host)
    if err != nil || addr.Zone() != "" || addr.Is4In6() { return false }
    ip := net.IP(addr.AsSlice())
    for _, network := range trusted {
        if network != nil && network.Contains(ip) { return true }
    }
    return false
}
