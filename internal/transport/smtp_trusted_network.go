package transport

import (
	"errors"
	"net"
	"strings"
)

// parseSMTPTrustedNetwork requires canonical network addresses. ParseCIDR
// otherwise silently masks host bits, expanding the set of trusted peers.
// IPv4-mapped IPv6 CIDRs are rejected: they are easy to confuse with native
// IPv4 prefixes, and net.IPNet.Contains normalizes mapped addresses.
func parseSMTPTrustedNetwork(value string) (*net.IPNet, error) {
	if strings.TrimSpace(value) != value || value == "" {
		return nil, errors.New("trusted network must not contain whitespace")
	}
	address, prefix, ok := strings.Cut(value, "/")
	if !ok || address == "" || prefix == "" {
		return nil, errors.New("trusted network requires an explicit CIDR prefix")
	}
	// Do not accept the mapped IPv6 spelling of an IPv4 trust rule.
	// Require the operator to spell the IPv4 range explicitly instead.
	if strings.Contains(address, ":") {
		ip := net.ParseIP(address)
		if ip != nil && ip.To4() != nil {
			return nil, errors.New("IPv4-mapped IPv6 trusted CIDR is ambiguous; use an IPv4 CIDR")
		}
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
