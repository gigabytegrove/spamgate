package transport

import (
 "errors"
 "net"
 "net/netip"
 "strings"
)

// parseSMTPTrustedNetwork accepts only explicit canonical network addresses.
// Host bits must never be silently masked into a broader trusted network.
func parseSMTPTrustedNetwork(value string) (*net.IPNet, error) {
 if value == "" || strings.TrimSpace(value) != value {
  return nil, errors.New("trusted network must not contain surrounding whitespace")
 }
 address, mask, found := strings.Cut(value, "/")
 if !found || address == "" || mask == "" || strings.Contains(mask, "/") {
  return nil, errors.New("trusted network requires one explicit CIDR prefix")
 }
 addr, err := netip.ParseAddr(address)
 if err != nil || addr.Zone() != "" || addr.Is4In6() {
  return nil, errors.New("trusted network requires an unambiguous IPv4 or IPv6 address")
 }
 // Dotted IPv4 embedded in an IPv6 ACL is ambiguous even when nonmapped.
 if addr.Is6() && strings.Contains(address, ".") {
  return nil, errors.New("trusted IPv6 CIDR must use hexadecimal address notation")
 }
 prefix, err := netip.ParsePrefix(value)
 if err != nil || !prefix.IsValid() || prefix.Addr() != addr {
  return nil, errors.New("invalid trusted network CIDR")
 }
 if prefix.Masked() != prefix {
  return nil, errors.New("trusted CIDR has host bits set; specify the network address or a single-host prefix")
 }
 bits := prefix.Bits()
 if addr.Is4() {
  return &net.IPNet{IP: net.IP(addr.AsSlice()), Mask: net.CIDRMask(bits, 32)}, nil
 }
 return &net.IPNet{IP: net.IP(addr.AsSlice()), Mask: net.CIDRMask(bits, 128)}, nil
}
