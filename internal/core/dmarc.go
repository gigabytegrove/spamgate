package core

// DMARC policy discovery and organizational-domain alignment. This is a
// transitional implementation: RFC 9989 t=y test mode is honored, but full
// DNS Tree Walk and PSD discovery are still outstanding. Public suffix rules
// may be overridden using SPAMGATE_PUBLIC_SUFFIX_FILE.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"time"
)

type DMARCResult struct {
	Result, Domain, Policy, Detail string
	// Testing records the current RFC 9989 t=y request. Historic pct
	// values are ignored; authentication evidence is never suppressed.
	Testing bool
}

func dmarcAligned(used, from, mode string) bool {
	used = strings.TrimSuffix(strings.ToLower(used), ".")
	from = strings.TrimSuffix(strings.ToLower(from), ".")
	if used == "" || from == "" {
		return false
	}
	if used == from {
		return true
	}
	if mode == "s" {
		return false
	}
	org := organizationalDomain(from)
	return org != "" && org == organizationalDomain(used)
}

// dmarcTXT discovers a single DMARC1 policy. An NXDOMAIN is absence, while a
// transient DNS problem must never be converted into DMARC authentication fail.
func dmarcTXT(ctx context.Context, resolver SPFResolver, name string) (string, error) {
	txts, err := resolver.LookupTXT(ctx, "_dmarc."+name)
	if err != nil {
		var dns *net.DNSError
		if errors.As(err, &dns) && dns.IsNotFound {
			return "", nil
		}
		return "", err
	}
	var record string
	for _, s := range txts {
		if dmarcCandidate(s) {
			if record != "" {
				return "", fmt.Errorf("%w: multiple DMARC1 policy TXT records", errDMARCPolicy)
			}
			record = s
		}
	}
	return record, nil
}

func DMARCCheck(ctx context.Context, resolver SPFResolver, headerFrom string, spf SPFResult, dkim []DKIMResult) DMARCResult {
	result := DMARCResult{Result: "none"}
	from, err := mail.ParseAddressList(headerFrom)
	if err != nil || len(from) != 1 {
		result.Detail = "DMARC requires exactly one valid RFC 5322 From identity"
		return result
	}
	address := from[0].Address
	p := strings.LastIndex(address, "@")
	if p < 0 {
		return result
	}
	domain := strings.ToLower(strings.TrimSuffix(address[p+1:], "."))
	result.Domain = domain
	if !isSubdomain(domain) {
		result.Detail = "Invalid From domain"
		return result
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dnsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	policyDomain := domain
	record, err := dmarcTXT(dnsCtx, resolver, domain)
	if err != nil {
		result.Result = "temperror"
		if errors.Is(err, errDMARCPolicy) {
			result.Result = "permerror"
		}
		result.Detail = "DMARC policy lookup failed: " + err.Error()
		return result
	}
	inherited := false
	if record == "" {
		org := organizationalDomain(domain)
		if org == "" || org == domain {
			result.Detail = "No DMARC policy found"
			return result
		}
		record, err = dmarcTXT(dnsCtx, resolver, org)
		if err != nil {
			result.Result = "temperror"
			if errors.Is(err, errDMARCPolicy) {
				result.Result = "permerror"
			}
			result.Detail = "Organizational DMARC policy lookup failed: " + err.Error()
			return result
		}
		if record == "" {
			result.Detail = "No DMARC policy at From domain or organizational domain"
			return result
		}
		policyDomain = org
		inherited = true
	}
	tags, err := parseDMARCRecord(record)
	if err != nil {
		result.Result = "permerror"
		result.Detail = "Invalid DMARC policy record: " + err.Error()
		return result
	}
	policy := strings.ToLower(tags["p"])
	if policy != "none" && policy != "quarantine" && policy != "reject" {
		result.Result = "permerror"
		result.Detail = "Invalid DMARC p policy"
		return result
	}
	subPolicy := strings.ToLower(tags["sp"])
	if subPolicy != "" && subPolicy != "none" && subPolicy != "quarantine" && subPolicy != "reject" {
		result.Result = "permerror"
		result.Detail = "Invalid DMARC sp policy"
		return result
	}
	if inherited && subPolicy != "" {
		policy = subPolicy
	}
	for _, k := range []string{"aspf", "adkim"} {
		if tags[k] != "" && tags[k] != "r" && tags[k] != "s" {
			result.Result = "permerror"
			result.Detail = "Invalid DMARC alignment mode"
			return result
		}
	}
	result.Policy = policy
	result.Testing = tags["t"] == "y"
	if spf.Result == "pass" && dmarcAligned(spf.Domain, domain, tags["aspf"]) {
		result.Result = "pass"
		result.Detail = "SPF authenticated an aligned organizational domain"
		return result
	}
	for _, sig := range dkim {
		if sig.Result == "pass" && dmarcAligned(sig.Domain, domain, tags["adkim"]) {
			result.Result = "pass"
			result.Detail = "DKIM authenticated an aligned organizational domain"
			return result
		}
	}
	// A network failure is not a verified authentication failure. Avoid
	// turning intermittent DNS failures into actionable false positives.
	if spf.Result == "temperror" {
		result.Result = "temperror"
		result.Detail = "SPF temporarily unavailable; cannot determine DMARC failure"
		return result
	}
	for _, sig := range dkim {
		if sig.Result == "temperror" {
			result.Result = "temperror"
			result.Detail = "DKIM temporarily unavailable; cannot determine DMARC failure"
			return result
		}
	}
	result.Result = "fail"
	result.Detail = fmt.Sprintf("DMARC authentication failed (policy domain %s; p=%s; SPF/DKIM not aligned)", policyDomain, policy)
	return result
}
