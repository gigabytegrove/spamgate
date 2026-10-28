package core

// SPF evaluation (RFC 7208): real DNS-based authorization of the SMTP envelope
// domain against the reported SMTP client IP. No authentication result is
// inferred from the message's From: header.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type SPFResolver interface {
	LookupTXT(context.Context, string) ([]string, error)
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
	LookupMX(context.Context, string) ([]*net.MX, error)
}

type SPFResult struct{ Result, Domain, Explanation string }

type spfEval struct {
	resolver SPFResolver
	lookups  int
	voids    int
}

func (e *spfEval) countDNS(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	e.lookups++
	if e.lookups > 10 {
		return errors.New("SPF DNS-mechanism lookup budget exceeded")
	}
	return nil
}
func (e *spfEval) countVoid(err error, n int) error {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound || err == nil && n == 0 {
		e.voids++
		if e.voids > 2 {
			return errors.New("SPF void DNS lookup budget exceeded")
		}
	}
	return nil
}
func spfDNSFailure(err error) string {
	if err == nil {
		return "none"
	}
	var d *net.DNSError
	if errors.As(err, &d) && d.IsNotFound {
		return "none"
	}
	return "temperror"
}
func isSubdomain(domain string) bool {
	return domain != "" && len(domain) <= 253 && !strings.ContainsAny(domain, "/ :@\\\t\r\n") && strings.Contains(domain, ".")
}
func SPFCheck(ctx context.Context, resolver SPFResolver, clientIP, sender, helo string) SPFResult {
	ip := net.ParseIP(strings.TrimSpace(clientIP))
	if ip == nil {
		return SPFResult{Result: "none", Explanation: "No validated SMTP client address available"}
	}
	domain := ""
	sender = strings.Trim(strings.TrimSpace(sender), "<>")
	if at := strings.LastIndex(sender, "@"); at >= 0 {
		domain = sender[at+1:]
	}
	if domain == "" {
		domain = helo
	} // null reverse-path: HELO identity
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if !isSubdomain(domain) {
		return SPFResult{Result: "none", Domain: domain, Explanation: "No valid envelope domain available"}
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dnsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	eval := &spfEval{resolver: resolver}
	result, detail := eval.evaluate(dnsCtx, ip, domain, map[string]bool{})
	return SPFResult{Result: result, Domain: domain, Explanation: detail}
}

// SPF a/mx mechanisms support different IPv4 and IPv6 prefix lengths.
// Exact-address matching silently breaks legitimate SPF a/24 or mx/24 records.
func spfAddressMatches(client net.IP, addresses []net.IPAddr, cidr string) (bool, error) {
	bits4, bits6 := 32, 128
	if cidr != "" {
		parts := strings.Split(cidr, "/")
		if len(parts) > 2 {
			return false, errors.New("invalid SPF dual-CIDR")
		}
		if parts[0] != "" {
			v, e := strconv.Atoi(parts[0])
			if e != nil || v < 0 || v > 32 {
				return false, errors.New("invalid SPF IPv4 prefix length")
			}
			bits4 = v
		}
		if len(parts) == 2 {
			v, e := strconv.Atoi(parts[1])
			if e != nil || v < 0 || v > 128 {
				return false, errors.New("invalid SPF IPv6 prefix length")
			}
			bits6 = v
		}
	}
	for _, entry := range addresses {
		a := entry.IP
		if ip4 := client.To4(); ip4 != nil {
			if candidate := a.To4(); candidate != nil {
				network := &net.IPNet{IP: candidate.Mask(net.CIDRMask(bits4, 32)), Mask: net.CIDRMask(bits4, 32)}
				if network.Contains(ip4) {
					return true, nil
				}
			}
		} else if candidate := a.To16(); candidate != nil && a.To4() == nil {
			network := &net.IPNet{IP: candidate.Mask(net.CIDRMask(bits6, 128)), Mask: net.CIDRMask(bits6, 128)}
			if network.Contains(client) {
				return true, nil
			}
		}
	}
	return false, nil
}

func (e *spfEval) evaluate(ctx context.Context, ip net.IP, domain string, seen map[string]bool) (string, string) {
	if seen[domain] {
		return "permerror", "SPF include/redirect cycle"
	}
	seen[domain] = true
	defer delete(seen, domain)
	txts, err := e.resolver.LookupTXT(ctx, domain)
	if err != nil {
		return spfDNSFailure(err), "TXT lookup: " + err.Error()
	}
	if err := e.countVoid(nil, len(txts)); err != nil {
		return "permerror", err.Error()
	}
	var record string
	for _, txt := range txts {
		if f := strings.Fields(txt); len(f) > 0 && strings.EqualFold(f[0], "v=spf1") {
			if record != "" {
				return "permerror", "Multiple SPF records"
			}
			record = txt
		}
	}
	if record == "" {
		return "none", "No SPF TXT record"
	}
	fields := strings.Fields(record)
	redirect := ""
	for _, term := range fields[1:] {
		if strings.HasPrefix(term, "redirect=") {
			redirect = strings.TrimPrefix(term, "redirect=")
			continue
		}
		if strings.HasPrefix(term, "exp=") {
			continue
		}
		qualifier := "pass"
		switch term[0] {
		case '-':
			qualifier = "fail"
			term = term[1:]
		case '~':
			qualifier = "softfail"
			term = term[1:]
		case '?':
			qualifier = "neutral"
			term = term[1:]
		case '+':
			term = term[1:]
		}
		mechanism, argument, _ := strings.Cut(term, ":")
		mask := ""
		if idx := strings.IndexByte(mechanism, '/'); idx >= 0 {
			mask = mechanism[idx+1:]
			mechanism = mechanism[:idx]
		}
		if idx := strings.IndexByte(argument, '/'); idx >= 0 {
			mask = argument[idx+1:]
			argument = argument[:idx]
		}
		match := false
		switch mechanism {
		case "all":
			match = true
		case "ip4", "ip6":
			if argument == "" {
				return "permerror", "Empty ip4/ip6 mechanism"
			}
			if mask == "" {
				if mechanism == "ip4" {
					mask = "32"
				} else {
					mask = "128"
				}
			}
			_, cidr, err := net.ParseCIDR(argument + "/" + mask)
			if err != nil {
				return "permerror", "Invalid SPF IP network"
			}
			if mechanism == "ip4" && cidr.IP.To4() == nil || mechanism == "ip6" && cidr.IP.To4() != nil {
				return "permerror", "SPF network address family mismatch"
			}
			match = cidr.Contains(ip)
		case "include":
			if !isSubdomain(argument) {
				return "permerror", "Invalid SPF include domain"
			}
			if err := e.countDNS(ctx); err != nil {
				return "permerror", err.Error()
			}
			result, reason := e.evaluate(ctx, ip, strings.ToLower(argument), seen)
			switch result {
			case "pass":
				match = true
			case "temperror", "permerror":
				return result, "SPF include " + argument + ": " + reason
			}
		case "a", "mx", "exists":
			target := domain
			if argument != "" {
				target = strings.ToLower(argument)
			}
			if !isSubdomain(target) {
				return "permerror", "Invalid SPF DNS mechanism domain"
			}
			if err := e.countDNS(ctx); err != nil {
				return "permerror", err.Error()
			}
			if mechanism == "mx" {
				records, err := e.resolver.LookupMX(ctx, target)
				if err != nil {
					return spfDNSFailure(err), "SPF MX lookup: " + err.Error()
				}
				if err := e.countVoid(nil, len(records)); err != nil {
					return "permerror", err.Error()
				}
				if len(records) > 10 {
					return "permerror", "SPF MX address lookup limit exceeded"
				}
				for _, mx := range records {
					if err := e.countDNS(ctx); err != nil {
						return "permerror", err.Error()
					}
					ips, err := e.resolver.LookupIPAddr(ctx, mx.Host)
					if err != nil {
						if spfDNSFailure(err) == "temperror" {
							return "temperror", err.Error()
						}
						continue
					}
					if err := e.countVoid(nil, len(ips)); err != nil {
						return "permerror", err.Error()
					}
					hit, e := spfAddressMatches(ip, ips, mask)
					if e != nil {
						return "permerror", e.Error()
					}
					if hit {
						match = true
					}
				}
			} else {
				ips, err := e.resolver.LookupIPAddr(ctx, target)
				if err != nil {
					if spfDNSFailure(err) == "temperror" {
						return "temperror", err.Error()
					}
					if err := e.countVoid(err, 0); err != nil {
						return "permerror", err.Error()
					}
					continue
				}
				if err := e.countVoid(nil, len(ips)); err != nil {
					return "permerror", err.Error()
				}
				if mechanism == "exists" {
					match = len(ips) > 0
				} else {
					hit, e := spfAddressMatches(ip, ips, mask)
					if e != nil {
						return "permerror", e.Error()
					}
					match = hit
				}
			}
		case "ptr":
			return "permerror", "Deprecated SPF ptr mechanism unsupported"
		default:
			return "permerror", "Unsupported SPF mechanism: " + mechanism
		}
		if match {
			return qualifier, fmt.Sprintf("SPF %s matched %s", qualifier, term)
		}
	}
	if redirect != "" {
		if !isSubdomain(redirect) {
			return "permerror", "Invalid SPF redirect"
		}
		if err := e.countDNS(ctx); err != nil {
			return "permerror", err.Error()
		}
		return e.evaluate(ctx, ip, strings.ToLower(redirect), seen)
	}
	return "neutral", "No SPF mechanism matched"
}
