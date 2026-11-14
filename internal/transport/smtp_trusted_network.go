package transport

import (
 "errors"
 "net"
 "strings"
)

// parseSMTPTrustedNetwork refuses non-canonical network prefixes. Go's
// ParseCIDR silently masks host bits (e.g. 192.0.2.5/24 becomes
// 192.0.2.0/24), which can trust more clients than an operator intended.
// A single trusted host must use an explicit /32 or /128 prefix.
func parseSMTPTrustedNetwork(value string) (*net.IPNet, error) {
 if strings.TrimSpace(value) != value || value == "" {
  return nil, errors.New("trusted network must not contain whitespace")
 }
 ip, network, err := net.ParseCIDR(value)
 if err != nil {
  return nil, err
 }
 if !ip.Equal(network.IP) {
  return nil, errors.New("trusted CIDR has host bits set; specify the network address or an explicit single-host prefix")
 }
 return network, nil
}
