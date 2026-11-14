package transport

import (
	"net/netip"
	"strings"
)

// parseSMTPXForwardAddress validates and normalizes Postfix XFORWARD ADDR.
// IPv4-mapped IPv6 is refused: normalizing it to IPv4 would change the
// advertised address family and could defeat identity-based policy checks.
func parseSMTPXForwardAddress(value string) (string, bool) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00\t") {
		return "", false
	}
	candidate := value
	if strings.HasPrefix(value, "[") || strings.HasSuffix(value, "]") {
		if len(value) < 3 || value[0] != '[' || value[len(value)-1] != ']' {
			return "", false
		}
		candidate = value[1 : len(value)-1]
	}
	ipv6Tagged := strings.HasPrefix(candidate, "IPv6:")
	if ipv6Tagged {
		candidate = strings.TrimPrefix(candidate, "IPv6:")
	} else if strings.Contains(candidate, "IPv6:") {
		return "", false
	}
	addr, err := netip.ParseAddr(candidate)
	if err != nil || addr.Zone() != "" || addr.Is4In6() || (ipv6Tagged && !addr.Is6()) {
		return "", false
	}
	return addr.String(), true
}
