package core

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// dnsblLookup queries an explicitly enabled IP DNSBL zone. The positive A
// response is valid only for the reserved 127/8 DNSBL result range. Arbitrary
// A answers (wildcard DNS, resolver redirects, captive portals) must NEVER
// be scored as a listing. No network call is made for disabled zones.
func dnsblLookup(ctx context.Context, resolver SPFResolver, clientIP, zone string) (string, bool, error) {
	v4 := net.ParseIP(clientIP).To4()
	if v4 == nil || !net.ParseIP(clientIP).IsGlobalUnicast() || net.ParseIP(clientIP).IsPrivate() {
		return "", false, nil
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	parts := []string{strconv.Itoa(int(v4[3])), strconv.Itoa(int(v4[2])), strconv.Itoa(int(v4[1])), strconv.Itoa(int(v4[0]))}
	q := strings.Join(parts, ".") + "." + strings.TrimSuffix(zone, ".")
	lookupCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	answers, err := resolver.LookupIPAddr(lookupCtx, q)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return q, false, nil
		}
		return q, false, err
	}
	for _, answer := range answers {
		ip := answer.IP.To4()
		if ip != nil && ip[0] == 127 && ip[1] != 255 && !(ip[1] == 0 && ip[2] == 0 && ip[3] == 1) {
			return fmt.Sprintf("%s returned %s", q, ip.String()), true, nil
		}
	}
	return q, false, nil
}

// ValidReputationDomain restricts administrator-supplied DNS zones and query
// domains to normal DNS hostnames. No URL, colon, whitespace or control input
// is concatenated into resolver queries.
func ValidReputationDomain(input string) bool {
	name := strings.TrimSuffix(strings.ToLower(input), ".")
	if len(name) < 4 || len(name) > 253 || net.ParseIP(name) != nil || !strings.Contains(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

// domainDNSBLLookup performs optional RHSBL or URIBL checks. A provider that
// does not supply DNSBL-style loopback responses cannot create a match.
func domainDNSBLLookup(ctx context.Context, resolver SPFResolver, name, zone string) (string, bool, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	if !ValidReputationDomain(name) || !ValidReputationDomain(zone) {
		return "", false, nil
	}
	if strings.HasSuffix(name, ".local") || strings.HasSuffix(name, ".internal") {
		return "", false, nil
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	query := name + "." + zone
	dnsCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	answers, err := resolver.LookupIPAddr(dnsCtx, query)
	if err != nil {
		if e, ok := err.(*net.DNSError); ok && e.IsNotFound {
			return query, false, nil
		}
		return query, false, err
	}
	for _, a := range answers {
		ip := a.IP.To4()
		if ip != nil && ip[0] == 127 && ip[1] != 255 && !(ip[1] == 0 && ip[2] == 0 && ip[3] == 1) {
			return fmt.Sprintf("%s returned %s", query, ip), true, nil
		}
	}
	return query, false, nil
}
