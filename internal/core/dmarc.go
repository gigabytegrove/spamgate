package core

// RFC 9989 DMARC policy discovery uses a bounded DNS Tree Walk and explicit
// PSD boundaries; unresolved DNS failures never become authentication failures.

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

// dmarcTXT discovers at most one DMARC1 policy. NXDOMAIN or conflicting
// policy TXT records mean absence at this name; transient errors remain inconclusive.
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
				// RFC 9989 section 4.10: discard all conflicting records
				// at this DNS name, allowing discovery at parent names.
				return "", nil
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
	walk := newDMARCDNSWalk(dnsCtx, resolver)
	policyDomain, fromOrg, tags, err := walk.discover(domain)
	if err != nil {
		result.Result = "temperror"
		if errors.Is(err, errDMARCPolicy) { result.Result = "permerror" }
		result.Detail = "DMARC DNS Tree Walk failed: " + err.Error()
		return result
	}
	if tags == nil {
		result.Detail = "No applicable DMARC policy discovered by DNS Tree Walk"
		return result
	}
	inherited := policyDomain != domain
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
	var alignmentErr error
	if spf.Result == "pass" {
		aligned, alignErr := walk.aligned(spf.Domain, domain, fromOrg, tags["aspf"])
		if aligned {
			result.Result = "pass"
			result.Detail = "SPF authenticated an aligned organizational domain"
			return result
		}
		alignmentErr = alignErr
	}
	for _, sig := range dkim {
		if sig.Result != "pass" { continue }
		aligned, alignErr := walk.aligned(sig.Domain, domain, fromOrg, tags["adkim"])
		if aligned {
			result.Result = "pass"
			result.Detail = "DKIM authenticated an aligned organizational domain"
			return result
		}
		if alignErr != nil { alignmentErr = alignErr }
	}
	if alignmentErr != nil {
		result.Result = "temperror"
		if errors.Is(alignmentErr, errDMARCPolicy) { result.Result = "permerror" }
		result.Detail = "DMARC identifier alignment DNS lookup failed: " + alignmentErr.Error()
		return result
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
